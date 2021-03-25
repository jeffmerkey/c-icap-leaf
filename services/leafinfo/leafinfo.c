/*
 *  Copyright (C) 2004-2009 Jeff Merkey
 */

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <semaphore.h>
#include <sys/mman.h>
#include <assert.h>
#include <ctype.h>
#include <errmsg.h>
#include <asm/errno.h>

#include "../../common.h"
#include "c_icap/c-icap.h"
#include "c_icap/service.h"
#include "c_icap/header.h"
#include "c_icap/body.h"
#include "c_icap/simple_api.h"
#include "c_icap/debug.h"

#include "srv_stats.h"

#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#define STATS_MEM_NAME "/leafstats"
#define SEM_MUTEX_NAME "/leafmutex"


struct leafinfo_req_data {
    ci_membuf_t *body;
    int text_mode;
};

int leafinfo_init_service(ci_service_xdata_t * srv_xdata,
                      struct ci_server_conf *server_conf);
int leafinfo_check_preview_handler(char *preview_data, int preview_data_len,
                               ci_request_t *);
int leafinfo_end_of_data_handler(ci_request_t * req);
void *leafinfo_init_request_data(ci_request_t * req);
void leafinfo_close_service();
void leafinfo_release_request_data(void *data);
int leafinfo_io(char *wbuf, int *wlen, char *rbuf, int *rlen, int iseof,
            ci_request_t * req);

CI_DECLARE_MOD_DATA ci_service_module_t service = {
    "leafinfo",                         /* mod_name, The module name */
    "LEAF Module run-time information",  /* mod_short_descr,  Module short description */
    ICAP_REQMOD,                    /* mod_type, The service type is request modification */
    leafinfo_init_service,              /* mod_init_service. Service initialization */
    NULL,                           /* post_init_service. Service initialization after c-icap
                    configured. Not used here */
    leafinfo_close_service,           /* mod_close_service. Called when service shutdowns. */
    leafinfo_init_request_data,         /* mod_init_request_data */
    leafinfo_release_request_data,      /* mod_release_request_data */
    leafinfo_check_preview_handler,     /* mod_check_preview_handler */
    leafinfo_end_of_data_handler,       /* mod_end_of_data_handler */
    leafinfo_io,                        /* mod_service_io */
    NULL,
    NULL
};

char *comma_snprintf(char *buffer, int size, const char *format, ...)
{
	register unsigned int len, i;
	char buf[1024], *src, *dest;
	register size_t vsize = size > (1024 - 1) ? 1024 - 1 : size;
	va_list ap;

	va_start(ap, format);
	len = vsnprintf((char *)buf, vsize, format, ap);
	va_end(ap);

	if (len)
	{
		src = buf + strlen((const char *)buf);
		dest = buffer + vsize;
		*dest = '\0';
		for (i=0; (i < strlen((const char *)buf)) && (dest >= buffer) && (src >= buf); i++)
		{
			if (i && !(i % 3))
				*--dest = ',';
				*--dest = *--src;
		}
		return (char *)dest;
	}
	return (char *)"";
}


int build_stats(struct leafinfo_req_data *leafinfo_data)
{
	GLOBAL *stats_ptr = NULL;
	sem_t *mutex_sem = NULL;
	int stats_shm;
	char buf[1024];
	char nbuf[1024], *w;

	if (!leafinfo_data->body)
		return 0;

	stats_shm = shm_open(STATS_MEM_NAME, O_RDWR, 0); 
	if (stats_shm > 0) {
		if ((stats_ptr = mmap(NULL, sizeof(GLOBAL), PROT_READ | PROT_WRITE, MAP_SHARED, stats_shm, 0)) == MAP_FAILED)
			stats_ptr = NULL;
	}	

	if ((mutex_sem = sem_open(SEM_MUTEX_NAME, 0, 0, 0)) == SEM_FAILED) {
		mutex_sem = NULL;
	}

	if (stats_ptr && mutex_sem) {
		if (sem_wait(mutex_sem) != -1) {
			if (leafinfo_data->text_mode) {
				snprintf(buf, sizeof(buf), "LEAF Server Statistics\n===========================\n");
				ci_membuf_write(leafinfo_data->body, buf, strlen(buf), 0);

				w = comma_snprintf(nbuf, sizeof(nbuf), "%lld", stats_ptr->pages_per_second);
				snprintf(buf, sizeof(buf), "pages/second: %s\n", w);
				ci_membuf_write(leafinfo_data->body, buf, strlen(buf), 0);

				w = comma_snprintf(nbuf, sizeof(nbuf), "%lld", stats_ptr->bytes_per_second);
				snprintf(buf, sizeof(buf), "bytes/second: %s\n", w);
				ci_membuf_write(leafinfo_data->body, buf, strlen(buf), 0);

				w = comma_snprintf(nbuf, sizeof(nbuf), "%lld", stats_ptr->dropped_per_second);
				snprintf(buf, sizeof(buf), "dropped/second: %s\n", w);
				ci_membuf_write(leafinfo_data->body, buf, strlen(buf), 0);

				w = comma_snprintf(nbuf, sizeof(nbuf), "%lld", stats_ptr->errors_per_second);
				snprintf(buf, sizeof(buf), "errors/second: %s\n", w);
				ci_membuf_write(leafinfo_data->body, buf, strlen(buf), 0);

				w = comma_snprintf(nbuf, sizeof(nbuf), "%lld", stats_ptr->aborts_per_second);
				snprintf(buf, sizeof(buf), "aborts/second: %s\n", w);
				ci_membuf_write(leafinfo_data->body, buf, strlen(buf), 0);

				w = comma_snprintf(nbuf, sizeof(nbuf), "%lld", stats_ptr->skipped_per_second);
				snprintf(buf, sizeof(buf), "skipped/second: %s\n", w);
				ci_membuf_write(leafinfo_data->body, buf, strlen(buf), 0);

				w = comma_snprintf(nbuf, sizeof(nbuf), "%lld", stats_ptr->total_pages);
				snprintf(buf, sizeof(buf), "total pages: %s\n", w);
				ci_membuf_write(leafinfo_data->body, buf, strlen(buf), 0);

				w = comma_snprintf(nbuf, sizeof(nbuf), "%lld", stats_ptr->total_bytes);
				snprintf(buf, sizeof(buf), "total bytes: %s\n", w);
				ci_membuf_write(leafinfo_data->body, buf, strlen(buf), 0);

				w = comma_snprintf(nbuf, sizeof(nbuf), "%lld", stats_ptr->total_dropped);
				snprintf(buf, sizeof(buf), "total dropped: %s\n", w);
				ci_membuf_write(leafinfo_data->body, buf, strlen(buf), 0);

				w = comma_snprintf(nbuf, sizeof(nbuf), "%lld", stats_ptr->total_errors);
				snprintf(buf, sizeof(buf), "total errors: %s\n", w);
				ci_membuf_write(leafinfo_data->body, buf, strlen(buf), 0);

				w = comma_snprintf(nbuf, sizeof(nbuf), "%lld", stats_ptr->total_aborts);
				snprintf(buf, sizeof(buf), "total aborts: %s\n", w);
				ci_membuf_write(leafinfo_data->body, buf, strlen(buf), 0);

				w = comma_snprintf(nbuf, sizeof(nbuf), "%lld", stats_ptr->total_skipped);
				snprintf(buf, sizeof(buf), "total skipped: %s\n", w);
				ci_membuf_write(leafinfo_data->body, buf, strlen(buf), 0);

				w = comma_snprintf(nbuf, sizeof(nbuf), "%lld", stats_ptr->total_allocation);
				snprintf(buf, sizeof(buf), "failed allocations: %s\n", w);
				ci_membuf_write(leafinfo_data->body, buf, strlen(buf), 0);

				w = comma_snprintf(nbuf, sizeof(nbuf), "%lld", stats_ptr->total_process);
				snprintf(buf, sizeof(buf), "failed processes: %s\n", w);
				ci_membuf_write(leafinfo_data->body, buf, strlen(buf), 0);

				w = comma_snprintf(nbuf, sizeof(nbuf), "%lld", stats_ptr->total_connection);
				snprintf(buf, sizeof(buf), "failed connections: %s\n", w);
				ci_membuf_write(leafinfo_data->body, buf, strlen(buf), 0);

				w = comma_snprintf(nbuf, sizeof(nbuf), "%lld", stats_ptr->total_queue);
				snprintf(buf, sizeof(buf), "queueing drops: %s\n", w);
				ci_membuf_write(leafinfo_data->body, buf, strlen(buf), 0);

				w = comma_snprintf(nbuf, sizeof(nbuf), "%lld", stats_ptr->avg_pages_per_second);
				snprintf(buf, sizeof(buf), "average pages/second: %s\n", w);
				ci_membuf_write(leafinfo_data->body, buf, strlen(buf), 0);

				w = comma_snprintf(nbuf, sizeof(nbuf), "%lld", stats_ptr->avg_bytes_per_second);
				snprintf(buf, sizeof(buf), "average bytes/second: %s\n", w);
				ci_membuf_write(leafinfo_data->body, buf, strlen(buf), 0);

				w = comma_snprintf(nbuf, sizeof(nbuf), "%lld", stats_ptr->avg_dropped_per_second);
				snprintf(buf, sizeof(buf), "average dropped/second: %s\n", w);
				ci_membuf_write(leafinfo_data->body, buf, strlen(buf), 0);

				w = comma_snprintf(nbuf, sizeof(nbuf), "%lld", stats_ptr->avg_errors_per_second);
				snprintf(buf, sizeof(buf), "average errors/second: %s\n", w);
				ci_membuf_write(leafinfo_data->body, buf, strlen(buf), 0);

				w = comma_snprintf(nbuf, sizeof(nbuf), "%lld", stats_ptr->avg_aborts_per_second);
				snprintf(buf, sizeof(buf), "average aborts/second: %s\n", w);
				ci_membuf_write(leafinfo_data->body, buf, strlen(buf), 0);

				w = comma_snprintf(nbuf, sizeof(nbuf), "%lld", stats_ptr->avg_skipped_per_second);
				snprintf(buf, sizeof(buf), "average skipped/second: %s\n", w);
				ci_membuf_write(leafinfo_data->body, buf, strlen(buf), 0);

				w = comma_snprintf(nbuf, sizeof(nbuf), "%lld", stats_ptr->peak_pages_per_second);
				snprintf(buf, sizeof(buf), "peak pages/second: %s\n", w);
				ci_membuf_write(leafinfo_data->body, buf, strlen(buf), 0);

				w = comma_snprintf(nbuf, sizeof(nbuf), "%lld", stats_ptr->peak_bytes_per_second);
				snprintf(buf, sizeof(buf), "peak bytes/second: %s\n", w);
				ci_membuf_write(leafinfo_data->body, buf, strlen(buf), 0);

				w = comma_snprintf(nbuf, sizeof(nbuf), "%lld", stats_ptr->peak_dropped_per_second);
				snprintf(buf, sizeof(buf), "peak dropped/second: %s\n", w);
				ci_membuf_write(leafinfo_data->body, buf, strlen(buf), 0);

				w = comma_snprintf(nbuf, sizeof(nbuf), "%lld", stats_ptr->peak_errors_per_second);
				snprintf(buf, sizeof(buf), "peak errors/second: %s\n", w);
				ci_membuf_write(leafinfo_data->body, buf, strlen(buf), 0);

				w = comma_snprintf(nbuf, sizeof(nbuf), "%lld", stats_ptr->peak_aborts_per_second);
				snprintf(buf, sizeof(buf), "peak aborts/second: %s\n", w);
				ci_membuf_write(leafinfo_data->body, buf, strlen(buf), 0);

				w = comma_snprintf(nbuf, sizeof(nbuf), "%lld", stats_ptr->peak_skipped_per_second);
				snprintf(buf, sizeof(buf), "peak skipped/second: %s\n", w);
				ci_membuf_write(leafinfo_data->body, buf, strlen(buf), 0);

				ci_membuf_write(leafinfo_data->body, "\n", 1, 0);
			}
			else {
				char *table_start = "<TABLE style=\"text-align:right;\">\n";
				char *table_end = "</TABLE>\n";

				snprintf(buf, sizeof(buf), "<H1>LEAF Server Statistics</H1>\n");
				ci_membuf_write(leafinfo_data->body, buf, strlen(buf), 0);

				ci_membuf_write(leafinfo_data->body, table_start, strlen(table_start), 0);

				w = comma_snprintf(nbuf, sizeof(nbuf), "%lld", stats_ptr->pages_per_second);
				snprintf(buf, sizeof(buf), "<TR><TH>pages/second:</TH><TD>%s</TD></TR>\n", w);
				ci_membuf_write(leafinfo_data->body, buf, strlen(buf), 0);

				w = comma_snprintf(nbuf, sizeof(nbuf), "%lld", stats_ptr->bytes_per_second);
				snprintf(buf, sizeof(buf), "<TR><TH>bytes/second:</TH><TD>%s</TD></TR>\n", w);
				ci_membuf_write(leafinfo_data->body, buf, strlen(buf), 0);

				w = comma_snprintf(nbuf, sizeof(nbuf), "%lld", stats_ptr->dropped_per_second);
				snprintf(buf, sizeof(buf), "<TR><TH>dropped/second:</TH><TD>%s</TD></TR>\n", w);
				ci_membuf_write(leafinfo_data->body, buf, strlen(buf), 0);

				w = comma_snprintf(nbuf, sizeof(nbuf), "%lld", stats_ptr->errors_per_second);
				snprintf(buf, sizeof(buf), "<TR><TH>errors/second:</TH><TD>%s</TD></TR>\n", w);
				ci_membuf_write(leafinfo_data->body, buf, strlen(buf), 0);

				w = comma_snprintf(nbuf, sizeof(nbuf), "%lld", stats_ptr->aborts_per_second);
				snprintf(buf, sizeof(buf), "<TR><TH>aborts/second:</TH><TD>%s</TD></TR>\n", w);
				ci_membuf_write(leafinfo_data->body, buf, strlen(buf), 0);

				w = comma_snprintf(nbuf, sizeof(nbuf), "%lld", stats_ptr->skipped_per_second);
				snprintf(buf, sizeof(buf), "<TR><TH>skipped/second:</TH><TD>%s</TD></TR>\n", w);
				ci_membuf_write(leafinfo_data->body, buf, strlen(buf), 0);

				w = comma_snprintf(nbuf, sizeof(nbuf), "%lld", stats_ptr->total_pages);
				snprintf(buf, sizeof(buf), "<TR><TH>total pages:</TH><TD>%s</TD></TR>\n", w);
				ci_membuf_write(leafinfo_data->body, buf, strlen(buf), 0);

				w = comma_snprintf(nbuf, sizeof(nbuf), "%lld", stats_ptr->total_bytes);
				snprintf(buf, sizeof(buf), "<TR><TH>total bytes:</TH><TD>%s</TD></TR>\n", w);
				ci_membuf_write(leafinfo_data->body, buf, strlen(buf), 0);

				w = comma_snprintf(nbuf, sizeof(nbuf), "%lld", stats_ptr->total_dropped);
				snprintf(buf, sizeof(buf), "<TR><TH>total dropped:</TH><TD>%s</TD></TR>\n", w);
				ci_membuf_write(leafinfo_data->body, buf, strlen(buf), 0);

				w = comma_snprintf(nbuf, sizeof(nbuf), "%lld", stats_ptr->total_errors);
				snprintf(buf, sizeof(buf), "<TR><TH>total errors:</TH><TD>%s</TD></TR>\n", w);
				ci_membuf_write(leafinfo_data->body, buf, strlen(buf), 0);

				w = comma_snprintf(nbuf, sizeof(nbuf), "%lld", stats_ptr->total_aborts);
				snprintf(buf, sizeof(buf), "<TR><TH>total aborts:</TH><TD>%s</TD></TR>\n", w);
				ci_membuf_write(leafinfo_data->body, buf, strlen(buf), 0);

				w = comma_snprintf(nbuf, sizeof(nbuf), "%lld", stats_ptr->total_skipped);
				snprintf(buf, sizeof(buf), "<TR><TH>total skipped:</TH><TD>%s</TD></TR>\n", w);
				ci_membuf_write(leafinfo_data->body, buf, strlen(buf), 0);

				w = comma_snprintf(nbuf, sizeof(nbuf), "%lld", stats_ptr->total_allocation);
				snprintf(buf, sizeof(buf), "<TR><TH>failed allocations:</TH><TD>%s</TD></TR>\n", w);
				ci_membuf_write(leafinfo_data->body, buf, strlen(buf), 0);

				w = comma_snprintf(nbuf, sizeof(nbuf), "%lld", stats_ptr->total_process);
				snprintf(buf, sizeof(buf), "<TR><TH>failed processes:</TH><TD>%s</TD></TR>\n", w);
				ci_membuf_write(leafinfo_data->body, buf, strlen(buf), 0);

				w = comma_snprintf(nbuf, sizeof(nbuf), "%lld", stats_ptr->total_connection);
				snprintf(buf, sizeof(buf), "<TR><TH>failed connections:</TH><TD>%s</TD></TR>\n", w);
				ci_membuf_write(leafinfo_data->body, buf, strlen(buf), 0);

				w = comma_snprintf(nbuf, sizeof(nbuf), "%lld", stats_ptr->total_queue);
				snprintf(buf, sizeof(buf), "<TR><TH>queueing drops:</TH><TD>%s</TD></TR>\n", w);
				ci_membuf_write(leafinfo_data->body, buf, strlen(buf), 0);

				w = comma_snprintf(nbuf, sizeof(nbuf), "%lld", stats_ptr->avg_pages_per_second);
				snprintf(buf, sizeof(buf), "<TR><TH>average pages/second:</TH><TD>%s</TD></TR>\n", w);
				ci_membuf_write(leafinfo_data->body, buf, strlen(buf), 0);

				w = comma_snprintf(nbuf, sizeof(nbuf), "%lld", stats_ptr->avg_bytes_per_second);
				snprintf(buf, sizeof(buf), "<TR><TH>average bytes/second:</TH><TD>%s</TD></TR>\n", w);
				ci_membuf_write(leafinfo_data->body, buf, strlen(buf), 0);

				w = comma_snprintf(nbuf, sizeof(nbuf), "%lld", stats_ptr->avg_dropped_per_second);
				snprintf(buf, sizeof(buf), "<TR><TH>average dropped/second:</TH><TD>%s</TD></TR>\n", w);
				ci_membuf_write(leafinfo_data->body, buf, strlen(buf), 0);

				w = comma_snprintf(nbuf, sizeof(nbuf), "%lld", stats_ptr->avg_errors_per_second);
				snprintf(buf, sizeof(buf), "<TR><TH>average errors/second:</TH><TD>%s</TD></TR>\n", w);
				ci_membuf_write(leafinfo_data->body, buf, strlen(buf), 0);

				w = comma_snprintf(nbuf, sizeof(nbuf), "%lld", stats_ptr->avg_aborts_per_second);
				snprintf(buf, sizeof(buf), "<TR><TH>average aborts/second:</TH><TD>%s</TD></TR>\n", w);
				ci_membuf_write(leafinfo_data->body, buf, strlen(buf), 0);

				w = comma_snprintf(nbuf, sizeof(nbuf), "%lld", stats_ptr->avg_skipped_per_second);
				snprintf(buf, sizeof(buf), "<TR><TH>average skipped/second:</TH><TD>%s</TD></TR>\n", w);
				ci_membuf_write(leafinfo_data->body, buf, strlen(buf), 0);

				w = comma_snprintf(nbuf, sizeof(nbuf), "%lld", stats_ptr->peak_pages_per_second);
				snprintf(buf, sizeof(buf), "<TR><TH>peak pages/second:</TH><TD>%s</TD></TR>\n", w);
				ci_membuf_write(leafinfo_data->body, buf, strlen(buf), 0);

				w = comma_snprintf(nbuf, sizeof(nbuf), "%lld", stats_ptr->peak_bytes_per_second);
				snprintf(buf, sizeof(buf), "<TR><TH>peak bytes/second:</TH><TD>%s</TD></TR>\n", w);
				ci_membuf_write(leafinfo_data->body, buf, strlen(buf), 0);

				w = comma_snprintf(nbuf, sizeof(nbuf), "%lld", stats_ptr->peak_dropped_per_second);
				snprintf(buf, sizeof(buf), "<TR><TH>peak dropped/second:</TH><TD>%s</TD></TR>\n", w);
				ci_membuf_write(leafinfo_data->body, buf, strlen(buf), 0);

				w = comma_snprintf(nbuf, sizeof(nbuf), "%lld", stats_ptr->peak_errors_per_second);
				snprintf(buf, sizeof(buf), "<TR><TH>peak errors/second:</TH><TD>%s</TD></TR>\n", w);
				ci_membuf_write(leafinfo_data->body, buf, strlen(buf), 0);

				w = comma_snprintf(nbuf, sizeof(nbuf), "%lld", stats_ptr->peak_aborts_per_second);
				snprintf(buf, sizeof(buf), "<TR><TH>peak aborts/second:</TH><TD>%s</TD></TR>\n", w);
				ci_membuf_write(leafinfo_data->body, buf, strlen(buf), 0);

				w = comma_snprintf(nbuf, sizeof(nbuf), "%lld", stats_ptr->peak_skipped_per_second);
				snprintf(buf, sizeof(buf), "<TR><TH>peak skipped/second:</TH><TD>%s</TD></TR>\n", w);
				ci_membuf_write(leafinfo_data->body, buf, strlen(buf), 0);

				ci_membuf_write(leafinfo_data->body, table_end, strlen(table_end), 0);
			}
			sem_post(mutex_sem);
		}
		ci_membuf_write(leafinfo_data->body, NULL, 0, 1);
	}

	if (mutex_sem) {
		sem_close(mutex_sem);
		mutex_sem = NULL;
	}

	if (stats_ptr) {
		munmap(stats_ptr, sizeof(GLOBAL));
		stats_ptr = NULL;
	} 
	if (stats_shm > 0) {
		close(stats_shm);
		stats_shm = 0;
	}
	return 1;
}

int leafinfo_init_service(ci_service_xdata_t * srv_xdata,
                      struct ci_server_conf *server_conf)
{
    ci_service_set_xopts(srv_xdata, CI_XAUTHENTICATEDUSER|CI_XAUTHENTICATEDGROUPS);
    return CI_OK;
}

void leafinfo_close_service()
{
    ci_debug_printf(5,"Service %s shutdown!\n", service.mod_name);
}

void *leafinfo_init_request_data(ci_request_t * req)
{
    struct leafinfo_req_data *leafinfo_data;

    leafinfo_data = malloc(sizeof(struct leafinfo_req_data));

    leafinfo_data->body = ci_membuf_new();
    if (leafinfo_data->body) {
	leafinfo_data->body->flags |= CI_MEMBUF_NULL_TERMINATED;
    }

    leafinfo_data->text_mode = 0;
    if (req->args[0] != '\0') {
        if (strstr(req->args, "view=text"))
            leafinfo_data->text_mode = 1;
    }
    return leafinfo_data;
}

void leafinfo_release_request_data(void *data)
{
    struct leafinfo_req_data *leafinfo_data = (struct leafinfo_req_data *)data;

    if (leafinfo_data->body)
        ci_membuf_free(leafinfo_data->body);

    free(leafinfo_data);
}


int leafinfo_check_preview_handler(char *preview_data, int preview_data_len,
                               ci_request_t * req)
{
    struct leafinfo_req_data *leafinfo_data = ci_service_data(req);

    if (ci_req_hasbody(req))
        return CI_MOD_ALLOW204;

    ci_req_unlock_data(req);

    ci_http_response_create(req, 1, 1); /*Build the response headers */

    ci_http_response_add_header(req, "HTTP/1.0 200 OK");
    ci_http_response_add_header(req, "Server: LEAF");
    ci_http_response_add_header(req, "Content-Type: text/html");
    ci_http_response_add_header(req, "Content-Language: en");
    ci_http_response_add_header(req, "Connection: close");
    if (leafinfo_data->body) {
	build_stats(leafinfo_data);
    }
    return CI_MOD_CONTINUE;
}

int leafinfo_end_of_data_handler(ci_request_t * req)
{
    return CI_MOD_DONE;
}

int leafinfo_io(char *wbuf, int *wlen, char *rbuf, int *rlen, int iseof,
            ci_request_t * req)
{
    int ret;
    struct leafinfo_req_data *leafinfo_data = ci_service_data(req);
    ret = CI_OK;

    if (wbuf && wlen) {
        if (leafinfo_data->body)
            *wlen = ci_membuf_read(leafinfo_data->body, wbuf, *wlen);
        else
            *wlen = CI_EOF;
    }

    return ret;
}

