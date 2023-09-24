
/*
 *  Copyright (C) 1997-2020 Jeffrey V. Merkey
 *  email: jeffmerkey@gmail.com
 */

#ifndef SRV_LEAF_H
#define SRV_LEAF_H
#endif

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#define RAW          0
#define DECODED      1
#define MODIFIED     2
#define ENCODED      3
#define CHUNKSZ      4096
#define MAXDATA	     4*1024*1024
#define MAXURL       8192

#define SIGNATURE          0xFEEDBEEF
#define CAPTURE_EN         0x01
#define MYSQL_DB           0x02
#define MSSQL_DB           0x04
#define COMPRESSION_EN     0x08
#define LICENSE_SEED	   "leaflib07131960123777!"

#define SHM_SIZE 0x10000
#define MAX_CPUS 256
#define MAX_PROCESSES 64

#define MAX_SQL_LENGTH        2048
#define MAX_SQL_HOSTNAME      256
#define MAX_SQL_DATABASE_NAME 64
#define MAX_SQL_TABLE_NAME    64
#define MAX_SQL_USER_NAME     80
#define MAX_SQL_PASSWORD      32
#define MAX_HTML_TITLE        512
#define MAX_PATH_LENGTH       4096

#define STATS_MEM_NAME "/leafstats"
#define SEM_MUTEX_NAME "/leafmutex"
#define MAX_ADAPTERS 256

struct leaf_req_data {
	struct ci_membuf *inbuf;
	struct ci_membuf *outbuf;
	struct ci_membuf *url;
	struct ci_membuf *ip;
	struct ci_membuf *account;
	struct ci_membuf *request;
	struct ci_membuf *response;
	struct ci_membuf *host;
	int whitelist;
	int enc_method;
	int eof;
};

typedef struct leaf_queue {
	struct leaf_queue *next;
	struct leaf_queue *prior;
	unsigned long elements;
	unsigned long long timestamp;
	void *con;
        unsigned long long len;
	char data[1];
} leaf_queue;

typedef struct leaf_queue_list {
	struct leaf_queue *head;
	struct leaf_queue *tail;
} leaf_queue_list;

typedef struct leaf_filter {
	struct leaf_filter *next;
	struct leaf_filter *prior;
        unsigned long long len;
	char data[1];
} leaf_filter;

typedef struct leaf_filter_list {
	struct leaf_filter *head;
	struct leaf_filter *tail;
} leaf_filter_list;

typedef struct connection_queue {
	struct connection_queue *next;
	struct connection_queue *prior;
	void *con;
        unsigned long status;
} connection_queue;

typedef struct connection_queue_list {
	struct connection_queue_list *head;
	struct connection_queue_list *tail;
	unsigned long connections;
	unsigned long max_connections;
} connection_queue_list;

extern int leaf_store_common(char *inbuf, size_t inlen, char *url, size_t ulen,
                      char *request, size_t reqlen, char *response, size_t reslen,
                      char *ip, int ilen, char *account, int alen, char *host, int hostlen, 
		      int whitelist);
extern void *leaf_connect(char *name);
extern void *leaf_close(void *con);
extern int init_database(void *con, int flags);
extern int leaf_store_log(char *inbuf, size_t inlen);

extern void init_maps(void);
extern void close_maps(void);
extern void child_open_maps(void);
extern void child_close_maps(void);
extern void init_stats(void);
extern void process_stats(void);
extern int leaf_lock(void);
extern int leaf_unlock(void);
extern void leaf_parse_options_file(void);

extern unsigned long long mysql_free_size(char *db_path);
extern int check_mysql_free_space(void);
extern void bypass_stats(size_t size);
void close_threads(void);

extern leaf_filter *add_filter(leaf_filter *filter, leaf_filter_list *list);
extern void free_filters(leaf_filter_list *list);
extern leaf_filter *search_filters(leaf_filter_list *list, unsigned char *haystack);
extern leaf_filter_list filter_include_list;
extern leaf_filter_list filter_exclude_list;

extern unsigned long pidtable[MAX_PROCESSES];
extern unsigned long pidindex;
extern unsigned long init_active;
extern unsigned long stats_active;
extern int numcpus;
extern int db_active;
extern int db_init_startup;
extern void *con;
extern unsigned long long mysql_free_space;
extern unsigned long long db_free_space_threshold;
extern unsigned long db_max_size;
extern unsigned long db_queue_depth;
extern unsigned long db_queue_threads;
extern unsigned long db_queue_mode;
extern unsigned long db_queue_sync;
extern unsigned long skip_length;
extern unsigned long condensed_max_length;
extern int show_skipped_requests;
extern int db_mode;
extern int leaf_bypass;
extern int mysql_bypass;
extern leaf_queue_list leaf_list;

extern char db_host[MAX_SQL_HOSTNAME+1];
extern char db_name[MAX_SQL_DATABASE_NAME+1];
extern char db_table[MAX_SQL_TABLE_NAME+1];
extern char db_user[MAX_SQL_USER_NAME+1];
extern char db_pass[MAX_SQL_PASSWORD+1];
extern char db_path[MAX_PATH_LENGTH+1];

