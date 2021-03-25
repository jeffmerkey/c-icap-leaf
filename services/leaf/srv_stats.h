
#define MAX_SQL_LENGTH        2048
#define MAX_SQL_HOSTNAME      256
#define MAX_SQL_DATABASE_NAME 64
#define MAX_SQL_TABLE_NAME    64
#define MAX_SQL_USER_NAME     80
#define MAX_SQL_PASSWORD      32
#define MAX_HTML_TITLE        512
#define MAX_PATH_LENGTH       4096

typedef struct _PAGESTATS
{
   unsigned long long pages;
   unsigned long long bytes;
   unsigned long long errors;
   unsigned long long dropped;
   unsigned long long aborts;
   unsigned long long skipped;
   unsigned long long allocation;
   unsigned long long process;
   unsigned long long connection;
   unsigned long long queue;
} PAGESTATS;

typedef struct _PROCESS_STATS
{
   unsigned long long pages_per_second;
   unsigned long long bytes_per_second;
   unsigned long long errors_per_second;
   unsigned long long dropped_per_second;
   unsigned long long aborts_per_second;
   unsigned long long skipped_per_second;
   PAGESTATS total;
   PAGESTATS current;
} PROCESS_STATS;

typedef struct _GLOBAL 
{
   unsigned long long pages_per_second;
   unsigned long long bytes_per_second;
   unsigned long long errors_per_second;
   unsigned long long dropped_per_second;
   unsigned long long aborts_per_second;
   unsigned long long skipped_per_second;
   unsigned long long total_pages;
   unsigned long long total_bytes;
   unsigned long long total_errors;
   unsigned long long total_dropped;
   unsigned long long total_aborts;
   unsigned long long total_skipped;
   unsigned long long total_allocation;
   unsigned long long total_process;
   unsigned long long total_connection;
   unsigned long long total_queue;
   unsigned long long peak_pages_per_second;
   unsigned long long peak_bytes_per_second;
   unsigned long long peak_errors_per_second;
   unsigned long long peak_dropped_per_second;
   unsigned long long peak_aborts_per_second;
   unsigned long long peak_skipped_per_second;
   unsigned long long avg_pages_per_second;
   unsigned long long avg_bytes_per_second;
   unsigned long long avg_errors_per_second;
   unsigned long long avg_dropped_per_second;
   unsigned long long avg_aborts_per_second;
   unsigned long long avg_skipped_per_second;
   PROCESS_STATS stats;
   char db_host[MAX_SQL_HOSTNAME+1];
   char db_name[MAX_SQL_DATABASE_NAME+1];
   char db_table[MAX_SQL_TABLE_NAME+1];
   char db_user[MAX_SQL_USER_NAME+1];
   char db_pass[MAX_SQL_PASSWORD+1];
   char db_path[MAX_PATH_LENGTH+1];
   unsigned long long mysql_free_space;
   unsigned long long db_free_space_threshold;
   unsigned long db_max_size;
   unsigned long skip_length;
   unsigned long condensed_max_length;
   unsigned long async_threads;
   unsigned long sync_threads;
   int show_skipped_requests;
   int db_mode;
   int db_init_startup;
   unsigned long long license;
   unsigned char license_data[128];
} GLOBAL;



