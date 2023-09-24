/*
 *  Copyright (C) 1997-2020 Jeffrey V. Merkey
 *  email: jeffmerkey@gmail.com
 *
 */

#include "../../common.h"
#include "c_icap/c-icap.h"
#include "c_icap/service.h"
#include "c_icap/header.h"
#include "c_icap/body.h"
#include "c_icap/simple_api.h"
#include "c_icap/debug.h"

#include <assert.h>
#include <ctype.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "srv_leaf.h"
#include "srv_stats.h"
#include "srv_strstr.h"

static int leaf_init_service(ci_service_xdata_t *srv_xdata,
				  struct ci_server_conf *server_conf);
static int leaf_post_init_service(ci_service_xdata_t *srv_xdata,
				       struct ci_server_conf *server_conf);
static int leaf_check_preview_handler(char *preview_data,
					   int preview_data_len,
					   ci_request_t *);
static int leaf_end_of_data_handler(ci_request_t *req);
static void *leaf_init_request_data(ci_request_t *req);
static void leaf_close_service();
static void leaf_release_request_data(void *data);
static int leaf_io(char *wbuf, int *wlen, char *rbuf, int *rlen, int iseof,
			ci_request_t *req);

//extern int ci_generic_compress_to_membuf(int encodeMethod, const char *inbuf, size_t inlen, ci_membuf_t *outbuf, ci_off_t max_size);
//extern int ci_generic_decompress_to_membuf(int encodeMethod, const char *inbuf, size_t inlen, ci_membuf_t *outbuf, ci_off_t max_size);
int (*ci_decode)(int encodeMethod, const char *inbuf, size_t inlen,
		 ci_membuf_t *outbuf, ci_off_t max_size) = ci_decompress_to_membuf;
int (*ci_encode)(int encodeMethod, const char *inbuf, size_t inlen,
		 ci_membuf_t *outbuf, ci_off_t max_size) = ci_compress_to_membuf;

/*
   The leaf_req_data structure will store the data required to serve an ICAP request.
   */
CI_DECLARE_MOD_DATA ci_service_module_t service = {
	"leaf",                            /* mod_name, The module name */
	"LEAF Monitoring Service",         /* mod_short_descr,  Module short description */
	ICAP_RESPMOD | ICAP_REQMOD,        /* mod_type, The service type is responce or request modification */
	leaf_init_service,                 /* mod_init_service. Service initialization */
	leaf_post_init_service,            /* post_init_service. Service initialization after c-icap configured. */
	leaf_close_service,                /* mod_close_service. Called when service shutdowns. */
	leaf_init_request_data,            /* mod_init_request_data */
	leaf_release_request_data,         /* mod_release_request_data */
	leaf_check_preview_handler,        /* mod_check_preview_handler */
	leaf_end_of_data_handler,          /* mod_end_of_data_handler */
	leaf_io,                           /* mod_service_io */
	NULL,			           /* configration variables table */
	NULL
};

unsigned long pidtable[MAX_PROCESSES];
unsigned long pidindex;
unsigned long init_active;
unsigned long stats_active;
int numcpus;
int db_active;
void *con;

static void init_signal_handler(int signo)
{
	switch (signo) {
	case SIGINT:
		ci_debug_printf(4, "leaf: got SIGINT pid %ld\n", (unsigned long) getpid());
		break;
	case SIGTERM:
		ci_debug_printf(4, "leaf: got SIGTERM pid %ld\n", (unsigned long) getpid());
                init_active = 0;
		break;
	case SIGHUP:
		ci_debug_printf(4, "leaf: got SIGHUP pid %ld\n", (unsigned long) getpid());
                init_active = 0;
		break;
        default:
		break;
	}
}

static void stats_signal_handler(int signo)
{
	switch (signo) {
	case SIGINT:
		ci_debug_printf(4, "leaf: got SIGINT pid %ld\n", (unsigned long) getpid());
		break;
	case SIGTERM:
		ci_debug_printf(4, "leaf: got SIGTERM pid %ld\n", (unsigned long) getpid());
                stats_active = 0;
		break;
	case SIGHUP:
		ci_debug_printf(4, "leaf: got SIGHUP pid %ld\n", (unsigned long) getpid());
                stats_active = 0;
		break;
        default:
		break;
	}
}

/* This function will be called when the service loaded  */
int leaf_init_service(ci_service_xdata_t * srv_xdata,
			   struct ci_server_conf *server_conf)
{
	int ret = CI_OK;

	ci_debug_printf(4, "leaf: initialization of leaf module parent %ld -> child %ld\n",
                        (unsigned long)getppid(), (unsigned long)getpid());

	leaf_parse_options_file();
        init_maps();

	/*Tell to the icap clients that we support 204 responses*/
	ci_service_enable_204(srv_xdata);

	/*Tell to the icap clients that we can support up to 1024 size of preview data*/
	ci_service_set_preview(srv_xdata, 1024);

	/*Tell to the icap clients to send preview data for all files*/
	ci_service_set_transfer_preview(srv_xdata, "*");

	/*Tell to the icap clients that we want the X-Authenticated-User and X-Authenticated-Groups headers
	  which contains the username and the groups in which belongs.  */
	ci_service_set_xopts(srv_xdata, CI_XCLIENTIP | CI_XSERVERIP | CI_XAUTHENTICATEDUSER | CI_XAUTHENTICATEDGROUPS);

        numcpus = sysconf(_SC_NPROCESSORS_ONLN);
        if (numcpus > MAX_CPUS)
           numcpus = MAX_CPUS;
	ci_debug_printf(4, "leaf: number of cpus detected %i\n", numcpus);
      
        con = NULL;
        db_active = 0;
    	return ret;
}

int leaf_post_init_service(ci_service_xdata_t * srv_xdata,
				struct ci_server_conf *server_conf)
{
	ci_debug_printf(4, "leaf: post initialization of leaf module......\n");

	char buf[1024];
        register int cpid, j, retries = 0;
        void *init_con = NULL;

        signal(SIGINT, init_signal_handler);
        signal(SIGTERM, init_signal_handler);
        signal(SIGHUP, init_signal_handler);

	init_con = leaf_connect(NULL);
	init_active = 1; 
	while (init_active) {
		if (init_con) {
			if (!(db_active = init_database(init_con, 0))) {
				snprintf(buf, sizeof(buf), "leaf: pid %ld could not initialize sql tables\n", (unsigned long)getpid());
				leaf_store_log(buf, strlen(buf));
				ci_debug_printf(4, "leaf: pid %ld could not initialize sql tables\n", (unsigned long)getpid());
			}
			else {
				snprintf(buf, sizeof(buf), "leaf: pid %ld initialized sql database\n", (unsigned long)getpid());
				leaf_store_log(buf, strlen(buf));
				ci_debug_printf(4, "leaf: pid %ld initialized sql database\n", (unsigned long)getpid());
			}
			break;
		}
		else { 
			if (retries++ > 3)
				break;
			if (sleep(1))
				break;
			init_con = leaf_connect(NULL);
		}
	}
	init_con = leaf_close(init_con);


	for (pidindex=j=0; j < 1; j++) {
		cpid = fork();
		if (!cpid) {
			signal(SIGTERM, stats_signal_handler);
			signal(SIGHUP, stats_signal_handler);

			if (prctl(PR_SET_PDEATHSIG, SIGHUP) < 0)
				ci_debug_printf(4, "leaf: could not register parent SIGHUP for pid %ld\n", (unsigned long) getpid());

			if (prctl(PR_SET_NAME, (unsigned long)"leafstats", 0, 0, 0) < 0) {
				ci_debug_printf(4, "leaf: could not set process name for pid %ld\n", (unsigned long) getpid());
			}
			ci_debug_printf(4, "leaf: leafstats process %i started pid %ld\n", j, (unsigned long) getpid());

			init_stats();
			stats_active = 1;
			while (stats_active) {
				process_stats();
				sleep(1);
			} 
			close_maps();
			exit(0);
		}
		else {
			pidtable[pidindex++] = cpid;                 
		}
	}
	return CI_OK;
}

/* This function will be called when the service shutdown */
void leaf_close_service()
{

	ci_debug_printf(4, "leaf: service shutdown parent %ld -> current pid %ld\n",
                        (unsigned long)getppid(),(unsigned long) getpid());
	close_threads();
        if (con)
	   con = leaf_close(con);
        child_close_maps();
	free_filters(&filter_include_list);
	free_filters(&filter_exclude_list);

#if DEBUG_CLOSE_STATS_PROCESS
        int i;
        for (i=0; i < pidindex; i++) {
           int status;
           ci_debug_printf(4, "leaf: sent SIGTERM to pid %ld\n", (unsigned long)pidtable[i]);                 
           kill(pidtable[i], SIGTERM);
           waitpid(pidtable[i], &status, 0);
        }
#endif

}

/*This function will be executed after the request served to release allocated data*/
void leaf_release_request_data(void *data)
{
	/*The data points to the leaf_req_data struct we allocated in function leaf_init_service */
	struct leaf_req_data *leaf_data =
		(struct leaf_req_data *)data;

	if (leaf_data->outbuf)
		ci_membuf_free(leaf_data->outbuf);

	if (leaf_data->inbuf)
		ci_membuf_free(leaf_data->inbuf);

	if (leaf_data->url)
		ci_membuf_free(leaf_data->url);

	if (leaf_data->ip)
		ci_membuf_free(leaf_data->ip);

	if (leaf_data->account)
		ci_membuf_free(leaf_data->account);

	if (leaf_data->request)
		ci_membuf_free(leaf_data->request);

	if (leaf_data->response)
		ci_membuf_free(leaf_data->response);

	if (leaf_data->host)
		ci_membuf_free(leaf_data->host);

	free(leaf_data);
}

/*This function will be executed when a new request for leaf service
  arrives. This function will initialize the required structures and data
  to serve the request.
  */
void *leaf_init_request_data(ci_request_t * req)
{
	struct leaf_req_data *leaf_data;

	/*Allocate memory for the leaf_data*/
	leaf_data = malloc(sizeof(struct leaf_req_data));
	if (!leaf_data) {
		ci_debug_printf(1, "leaf: memory allocation failed inside leaf_init_request_data!\n");
		return NULL;
	}

	leaf_data->inbuf = NULL;
	leaf_data->outbuf = NULL;
        leaf_data->url = NULL;
        leaf_data->ip = NULL;
        leaf_data->account = NULL;
        leaf_data->request = NULL;
        leaf_data->response = NULL;
        leaf_data->host = NULL;
	leaf_data->enc_method = CI_ENCODE_NONE;
	leaf_data->eof = 0;
	leaf_data->whitelist = 0;

	/*If the ICAP request encuspulates a HTTP objects which contains body data
	  and not only headers allocate a ci_cached_file_t object to store the body data.
	  */
	leaf_data->inbuf = ci_membuf_new(0);
	if (!leaf_data->inbuf) {
		ci_debug_printf(1, "leaf: membuf allocation failed inside leaf_init_request_data!\n");
		leaf_release_request_data(leaf_data);
		return NULL;
	}
	ci_membuf_set_flag(leaf_data->inbuf, CI_MEMBUF_NULL_TERMINATED);

	leaf_data->outbuf = ci_membuf_new(0);
	if (!leaf_data->outbuf) {
		ci_debug_printf(1, "leaf: membuf allocation failed inside leaf_init_request_data!\n");
		leaf_release_request_data(leaf_data);
		return NULL;
	}
	ci_membuf_set_flag(leaf_data->outbuf, CI_MEMBUF_NULL_TERMINATED);

	leaf_data->url = ci_membuf_new_sized(MAXURL);
	if (!leaf_data->url) {
		ci_debug_printf(1, "leaf: membuf allocation failed inside leaf_init_request_data!\n");
		leaf_release_request_data(leaf_data);
		return NULL;
	}
	ci_membuf_set_flag(leaf_data->url, CI_MEMBUF_NULL_TERMINATED);

	leaf_data->ip = ci_membuf_new_sized(0);
	if (!leaf_data->ip) {
		ci_debug_printf(1, "leaf: membuf allocation failed inside leaf_init_request_data!\n");
		leaf_release_request_data(leaf_data);
		return NULL;
	}
	ci_membuf_set_flag(leaf_data->ip, CI_MEMBUF_NULL_TERMINATED);

	leaf_data->account = ci_membuf_new_sized(0);
	if (!leaf_data->account) {
		ci_debug_printf(1, "leaf: membuf allocation failed inside leaf_init_request_data!\n");
		leaf_release_request_data(leaf_data);
		return NULL;
	}
	ci_membuf_set_flag(leaf_data->account, CI_MEMBUF_NULL_TERMINATED);

	leaf_data->request = ci_membuf_new_sized(0);
	if (!leaf_data->request) {
		ci_debug_printf(1, "leaf: membuf allocation failed inside leaf_init_request_data!\n");
		leaf_release_request_data(leaf_data);
		return NULL;
	}
	ci_membuf_set_flag(leaf_data->request, CI_MEMBUF_NULL_TERMINATED);

	leaf_data->response = ci_membuf_new_sized(0);
	if (!leaf_data->response) {
		ci_debug_printf(1, "leaf: membuf allocation failed inside leaf_init_request_data!\n");
		leaf_release_request_data(leaf_data);
		return NULL;
	}
	ci_membuf_set_flag(leaf_data->response, CI_MEMBUF_NULL_TERMINATED);

	leaf_data->host = ci_membuf_new_sized(0);
	if (!leaf_data->host) {
		ci_debug_printf(1, "leaf: membuf allocation failed inside leaf_init_request_data!\n");
		leaf_release_request_data(leaf_data);
		return NULL;
	}
	ci_membuf_set_flag(leaf_data->host, CI_MEMBUF_NULL_TERMINATED);

	/*Return to the c-icap server the allocated data*/
	return leaf_data;
}

int leaf_check_preview_handler(char *preview_data, int preview_data_len,
				    ci_request_t * req)
{
	/*Get the leaf_req_data we allocated using the  leaf_init_service  function*/
	struct leaf_req_data *leaf_data = ci_service_data(req);

	/*If no content type or the content type is not html do not process */
	const char *content_type = ci_http_response_get_header(req, "Content-Type");
	const char *contentEncoding = ci_http_response_get_header(req, "Content-Encoding");
	const char *content_length = ci_http_response_get_header(req, "Content-Length");
	if (content_length) {};

	if (check_mysql_free_space()) {
		//ci_debug_printf(4, "leaf: mysql free space beneath out of space threshold, skipping request\n");
		return CI_MOD_ALLOW204;
	}

        // if Content-Type missing do not process
	if (!content_type) {
		return CI_MOD_ALLOW204;
	}

	// If there is no body data in HTTP encapsulated object but only headers
        // respond with Allow204 (no modification required) and terminate here the
	// ICAP transaction 
	if (!ci_req_hasbody(req)) {
		return CI_MOD_ALLOW204;
	}

        if (strcasestr(content_type, "text/html")) {
                int i;
	        ci_headers_list_t *response_head = ci_http_response_headers(req);
                
                // check for 200 return code and allow only pages with this status                  
                if (response_head && response_head->headers[0] && !strcasestr(response_head->headers[0], "200")) {
		   ci_debug_printf(4, "leaf: response header was \"%s\" return allow 204 pid:%ld\n",
				 response_head->headers[0], (unsigned long)getpid());
  		   return CI_MOD_ALLOW204;
		}
#ifdef SHOW_ICAP_HEADERS
    		for (i = 0; i < req->request_header->used; i++) {
		      ci_debug_printf(4, "leaf: (%i) %s\n", i, req->request_header->headers[i]);
		}
#endif
		const char *content_length = ci_http_response_get_header(req, "Content-Length");
		//const char *host = ci_headers_value(req->request_header, "X-Server-IP");
		const char *host = ci_headers_value(req->request_header, "Host");
	        if (host && leaf_data->host) {
			ci_membuf_write(leaf_data->host, host, strlen(host), 1);
		}

	        ci_headers_list_t *request_head = ci_http_request_headers(req);
	        if (leaf_data->url) {
			leaf_filter *filter;
		        leaf_data->url->endpos = ci_http_request_url(req, leaf_data->url->buf, MAXURL);
			// if specified to include from this domain, mark as whitelisted
			if ((filter = search_filters(&filter_include_list, (unsigned char *)leaf_data->url->buf))) {
				leaf_data->whitelist = 1;
				ci_debug_printf(4, "leaf: include filter match (%s) pid:%ld\n", filter->data,
					(unsigned long)getpid());
			}
			else
			if ((filter = search_filters(&filter_exclude_list, (unsigned char *)leaf_data->url->buf))) {
				ci_debug_printf(4, "leaf: exclude filter match (%s) return allow 204 pid:%ld\n", filter->data,
					(unsigned long)getpid());
				return CI_MOD_ALLOW204;
			}
		}

		char *ip = (char *)ci_headers_value(req->request_header, "X-Client-IP");
		if (ip && leaf_data->ip) { 
			ci_membuf_write(leaf_data->ip, ip, strlen(ip), 1);
		}

		char *account = (char *)ci_headers_value(req->request_header, "X-Authenticated-User");
	        if (account && leaf_data->account) {
			ci_membuf_write(leaf_data->account, account, strlen(account), 1);
		}

	        if (request_head && leaf_data->request)  {
                   for (i=0; request_head && i < request_head->used; i++) {
                      int len = strlen(request_head->headers[i]);
                      if (len) {
		         ci_membuf_write(leaf_data->request, request_head->headers[i], len, 0);
		         ci_membuf_write(leaf_data->request, "\n", 1, 0);
                      }
                   }
                }

	        if (response_head && leaf_data->response)  {
                   for (i=0; response_head && i < response_head->used; i++) {
                      int len = strlen(response_head->headers[i]);
                      if (len) {
		         ci_membuf_write(leaf_data->response, response_head->headers[i], len, 0);
		         ci_membuf_write(leaf_data->response, "\n", 1, 0);
                      }
                   }
                }

		ci_debug_printf(4, "leaf: Content-Type: %s Content-Encoding: %s Content-Length: %s IP: %s pid: %ld\n", 
			content_type,
                        contentEncoding ? contentEncoding : "UNCOMPRESSED",
			content_length ? content_length : "UNSPECIFIED",
			leaf_data->ip && leaf_data->ip->endpos ? leaf_data->ip->buf : "UNKNOWN",
                        (unsigned long)getpid());

		ci_debug_printf(4, "leaf: account: %s url: %s host: %s\n",
			leaf_data->account && leaf_data->account->endpos ? leaf_data->account->buf : "NONE",
                        leaf_data->url && leaf_data->url->endpos ? leaf_data->url->buf : "NONE",
                        host ? host : "NONE");

#ifdef SHOW_HTTP_HEADERS
		ci_debug_printf(4, "leaf: HTTP Request Headers\n");
                for (i=0; request_head && i < request_head->used; i++) {
                   int len = strlen(request_head->headers[i]);
                   if (len)
		      ci_debug_printf(4, "leaf: (%i) %s\n", i, request_head->headers[i]);
                }

		ci_debug_printf(4, "leaf: HTTP Response Headers\n");
                for (i=0; response_head && i < response_head->used; i++) {
                   int len = strlen(response_head->headers[i]);
                   if (len)
		      ci_debug_printf(4, "leaf: (%i) %s\n", i, response_head->headers[i]);
                }
#endif
        } else {
		if (show_skipped_requests) {
#ifdef SHOW_SKIPPED_DETAIL 
			const char *host = ci_headers_value(req->request_header, "X-Server-IP");
		        if (leaf_data->url) {
			        leaf_data->url->endpos = ci_http_request_url(req, leaf_data->url->buf, MAXURL);
			}

			char *ip = (char *)ci_headers_value(req->request_header, "X-Client-IP");
			if (ip && leaf_data->ip) { 
				ci_membuf_write(leaf_data->ip, ip, strlen(ip), 0);
				ci_membuf_write(leaf_data->ip, "\0", 1, 1);
			}

			char *account = (char *)ci_headers_value(req->request_header, "X-Authenticated-User");
		        if (account && leaf_data->account) {
				ci_membuf_write(leaf_data->account, account, strlen(account), 0);
				ci_membuf_write(leaf_data->account, "\0", 1, 1);
			}
#endif
			ci_debug_printf(4, "leaf: Content-Type: %s Content-Encoding: %s Content-Length: %s, return allow 204\n",
				content_type, contentEncoding ? contentEncoding : "UNCOMPRESSED",
				content_length ? content_length : "UNSPECIFIED");
#ifdef SHOW_SKIPPED_DETAIL 
			ci_debug_printf(4, "leaf: IP: %s account: %s url: %s host: %s\n",
				leaf_data->ip && leaf_data->ip->endpos ? leaf_data->ip->buf : "UNKNOWN",
				leaf_data->account && leaf_data->account->endpos ? leaf_data->account->buf : "NONE",
                        	leaf_data->url && leaf_data->url->endpos ? leaf_data->url->buf : "NONE",
	                        host ? host : "NONE");
#endif
		}
		return CI_MOD_ALLOW204;
	}

	// If there is a Content-Length header, check it we do not want to
	// process body data with more than MaxBodyData size
	ci_off_t content_len = ci_http_content_length(req);
	ci_debug_printf(4, "leaf: expected length: %"PRINTF_OFF_T"\n",
			(CAST_OFF_T) content_len);

	leaf_data->enc_method = CI_ENCODE_NONE;
	if (contentEncoding) {
		if (strcasestr(contentEncoding, "deflate")) {
			leaf_data->enc_method = CI_ENCODE_DEFLATE;
		} else if (strcasestr(contentEncoding, "gzip")) {
			leaf_data->enc_method = CI_ENCODE_GZIP;
		} else if (strcasestr(contentEncoding, "bzip2") ||
			   strcasestr(contentEncoding, "bzip")) {
			leaf_data->enc_method = CI_ENCODE_BZIP2;
		} else if (strcasestr(contentEncoding, "br")) {
			leaf_data->enc_method = CI_ENCODE_BROTLI;
		} else {
			// if unknown compression method, skip the request
			ci_debug_printf(4, "leaf: Content-Encoding %s is unsupported.\n",
					contentEncoding);
			return CI_MOD_ALLOW204;
		}
	}

	/*if we have preview data and we want to proceed with the request processing
	  we should store the preview data. There are cases where all the body
	  data of the encapsulated HTTP object included in preview data. Someone can use
	  the ci_req_hasalldata macro to  identify these cases
	  */
	if (preview_data_len) {
		ci_membuf_write(leaf_data->inbuf, preview_data,
				preview_data_len, ci_req_hasalldata(req));
		leaf_data->eof = ci_req_hasalldata(req);
	}
	return CI_MOD_CONTINUE;
}

/* This function will called if we returned CI_MOD_CONTINUE in
   leaf_check_preview_handler function, after we read all the data from
   the ICAP client
   */
int leaf_end_of_data_handler(ci_request_t *req)
{
	struct leaf_req_data *leaf_data = ci_service_data(req);
	int ccode = 0;

	ci_debug_printf(4, "leaf: end of data handler called body size: %lld\n",(long long int)leaf_data->inbuf->endpos);

	if (leaf_bypass) {
	 	bypass_stats(leaf_data->inbuf->endpos);
        	if (req->allow204 && !ci_req_sent_data(req)) {
			//ci_debug_printf(4, "leaf: end of data handler returned ALLOW204 response\n");
			return CI_MOD_ALLOW204;
	        }
		leaf_data->eof = 1;
		ci_req_unlock_data(req);
		return CI_MOD_DONE;
	}

	// if compressed, then decompress the data before sending it to the translator module
	switch (leaf_data->enc_method) {
	case CI_ENCODE_DEFLATE:
	case CI_ENCODE_GZIP:
	case CI_ENCODE_BZIP2:
	case CI_ENCODE_BROTLI:
		ccode = ci_decode(leaf_data->enc_method,
				  leaf_data->inbuf->buf,
				  leaf_data->inbuf->endpos,
				  leaf_data->outbuf,
				  MAXDATA);
		if (ccode == CI_UNCOMP_OK) {
                   leaf_store_common(
                              leaf_data->outbuf->buf,
                              leaf_data->outbuf->endpos,
                              leaf_data->url->buf,
                              leaf_data->url->endpos,
                              leaf_data->request->buf,
                              leaf_data->request->endpos, 
                              leaf_data->response->buf,
                              leaf_data->response->endpos, 
                              leaf_data->ip->buf,
                              leaf_data->ip->endpos,
                              leaf_data->account->buf,
                              leaf_data->account->endpos,
                              leaf_data->host->buf,
                              leaf_data->host->endpos,
			      leaf_data->whitelist);
		} else {
			ci_debug_printf(4, "leaf: decompression error.  skipping request ...\n");
		}
		break;
	case CI_ENCODE_UNKNOWN:
	case CI_ENCODE_NONE:
	default:
                leaf_store_common(
			  leaf_data->inbuf->buf,
                          leaf_data->inbuf->endpos,
                          leaf_data->url->buf,
                          leaf_data->url->endpos,
                          leaf_data->request->buf,
                          leaf_data->request->endpos, 
                          leaf_data->response->buf,
                          leaf_data->response->endpos, 
                          leaf_data->ip->buf,
                          leaf_data->ip->endpos,
                          leaf_data->account->buf,
                          leaf_data->account->endpos,
                          leaf_data->host->buf,
                          leaf_data->host->endpos,
			  leaf_data->whitelist);
		break;
	}
        if (req->allow204 && !ci_req_sent_data(req)) {
		//ci_debug_printf(4, "leaf: end of data handler returned ALLOW204 response\n");
		return CI_MOD_ALLOW204;
        }
	/*mark the eof*/
	leaf_data->eof = 1;
	/*Unlock the request body data so the c-icap server can send data*/
	ci_req_unlock_data(req);
	/*and return CI_MOD_DONE */
	//ci_debug_printf(4, "leaf: end of data handler returned MOD_DONE response\n");
	return CI_MOD_DONE;
}

/* This function will called if we returned CI_MOD_CONTINUE in leaf_check_preview_handler
   function, when new data arrived from the ICAP client and when the ICAP client is
   ready to get data.
   */
int leaf_io(char *wbuf, int *wlen, char *rbuf, int *rlen, int iseof,
		 ci_request_t * req)
{
	int ret;
	struct leaf_req_data *leaf_data = ci_service_data(req);
	ret = CI_OK;
#ifdef SHOW_LEAF_IO
	ci_debug_printf(4, "leaf: io called write -> %p %d  read -> %p %d eof: %d\n",
			wbuf, wlen ? *wlen : 0,	rbuf, rlen ? *rlen : 0,	iseof);
#endif
	/*write the data read from icap_client to the leaf_data->inbuf*/
	if (rlen && rbuf) {
		*rlen = ci_membuf_write(leaf_data->inbuf, rbuf,
					*rlen, iseof);
		if (*rlen < 0)
			ret = CI_ERROR;
	}

	/*Do not send any data if we do not receive all of the data*/
	if (!leaf_data->eof)
		return ret;

	/*read some data from the leaf_data->body and put them to the write buffer to be send
	  to the ICAP client*/
	if (wbuf && wlen) {
		*wlen = ci_membuf_read(leaf_data->inbuf, wbuf, *wlen);
	}

	if (*wlen==0 && leaf_data->eof==1)
		*wlen = CI_EOF;

	return ret;
}

