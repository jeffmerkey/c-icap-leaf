
/*
 *  Copyright (C) 1997-2020 Jeffrey V. Merkey
 *  email: jeffmerkey@gmail.com
 *
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
#include <regex.h>
#include <errno.h>

#include <mysql.h>
#include <mysqld_error.h>
#include <errmsg.h>

#include <sys/vfs.h>
#include <sys/statvfs.h>
#include <pthread.h>

#include "srv_leaf.h"
#include "srv_stats.h"
#include "srv_strstr.h"
#include "c_icap/debug.h"

#define MIN_QUEUE_THREADS 4
#define MAX_QUEUE_THREADS 64

char db_host[MAX_SQL_HOSTNAME+1]      = "127.0.0.1";
char db_name[MAX_SQL_DATABASE_NAME+1] = "leafpage";
char db_table[MAX_SQL_TABLE_NAME+1]   = "capture";
char db_user[MAX_SQL_USER_NAME+1]     = "root";
char db_pass[MAX_SQL_PASSWORD+1]      = "";
char db_path[MAX_PATH_LENGTH+1]       = "/var/lib/mysql";

unsigned long long mysql_free_space = 0;
unsigned long long db_free_space_threshold = 1073741824;
unsigned long db_max_size = 0;
unsigned long db_queue_depth = 10;
unsigned long db_queue_threads = 4;
unsigned long db_queue_mode = 0;
unsigned long db_queue_sync = 0;
unsigned long skip_length = 1024;
unsigned long condensed_max_length = 0;
int show_skipped_requests = 0;
int db_mode = 0;
#if 0
int db_init_startup = 0;
#endif

// Debug variables
int leaf_bypass = 0;
int mysql_bypass = 0;

GLOBAL global;
GLOBAL *stats_ptr;
int *stats_fd;
int stats_shm;
sem_t *mutex_sem;

void *leaf_connect(char *name)
{
        MYSQL *con;

        con = mysql_init(NULL);
        if (con == NULL) 
        {
		ci_debug_printf(4, "leaf: open sql database library failed %s\n", mysql_error(con));
        }
        else
        if (mysql_real_connect(con, db_host, db_user, db_pass, name, 0, NULL, CLIENT_MULTI_STATEMENTS) == NULL) 
        {
		ci_debug_printf(4, "leaf: pid %ld could not connect to sql database %s\n", (unsigned long) getpid(), mysql_error(con));
		con = leaf_close(con);
        }
        if (con) {
		ci_debug_printf(4, "leaf: pid %ld connected to sql database %s\n", (unsigned long)getpid(), mysql_error(con));
		if (mysql_set_character_set(con, "utf8mb4")) {
			ci_debug_printf(4, "%s\n", mysql_error(con));
			con = leaf_close(con);
		}
	}
        return con;
} 

void *leaf_close(void *con)
{
        if (con) {
		ci_debug_printf(4, "leaf: pid %ld closing sql connection\n", (unsigned long) getpid());
		mysql_close(con);
		con = NULL;
        }
        return con;
}

int leaf_parse_mysql_file(void)
{
	char buffer[1024];
	FILE *fp;
	register int flag = 0;

	fp = fopen("/etc/my.cnf", "rb");
	while (fp && !feof(fp))
	{
		if (fgets(buffer, 1024, fp)) 
		{
			int count;
			char temp[1024], *src, *dest;
			temp[0] = '\0';
			count = 0;
			src = buffer;
			dest = temp;

			// strip out all spaces and punc characters
			while (*src) {
				if (++count > 1024)
					break;
				if ((*src == '\n') || (*src == ' ') || (*src == '\t') ||
					 (*src == '\r') || (*src == ';') || (*src == ',')) {
					src++;
				}
				else				
					*dest++ = *src++;
			}
			*dest = '\0';

			// skip empty lines
			if (!temp[0])
				continue;

			// skip comments
			if (!strncasecmp(temp, "#", 1))
				continue;

			if (!strncasecmp(temp, "[mysqld]", 8)) {
				flag++;
			}
			else if (!strncasecmp(temp, "datadir=", 8) && flag) {
				strncpy(db_path, &temp[8], MAX_PATH_LENGTH+1);
				fclose(fp);
				return 0;
			}
			else if (!strncasecmp(temp, "[", 1)) {
				// if new section, clear mysqld flag
				flag = 0;
			}
		}
	}
	if (fp) {
		fclose(fp);
	}
	return 1;

}


unsigned long long mysql_free_size(char *db_path)
{
	unsigned long long len = 0;
	struct statvfs stat;

	if (!statvfs(db_path, &stat)) {
		len = (unsigned long long)stat.f_bavail * stat.f_frsize;
		return len;
	}
	return len;
}

int check_mysql_free_space(void)
{
	if (!db_free_space_threshold) 
		return 0;

	mysql_free_space = mysql_free_size(db_path);
	if (mysql_free_space < db_free_space_threshold) {
		ci_debug_printf(4, "leaf: sql remaing free space (%llu) beneath threshold (%llu)\n",
				mysql_free_space, db_free_space_threshold);
		if (stats_ptr) {
			stats_ptr->stats.total.dropped++;
		}
		return 1;
	}
	return 0;
}

leaf_filter_list filter_include_list;
leaf_filter_list filter_exclude_list;

leaf_filter *add_filter(leaf_filter *filter, leaf_filter_list *list)
{
	if (!list->head)
	{
		list->head = filter;
		list->tail = filter;
		filter->next = filter->prior = NULL;
	}
	else
	{
		list->tail->next = filter;
		filter->next = NULL;
		filter->prior = list->tail;
		list->tail = filter;
	}
	return filter;
}

void free_filters(leaf_filter_list *list)
{
	leaf_filter *filter;

	while (list->head) {
		filter = list->head;
		list->head = filter->next;
		free(filter);
	}
	list->head = list->tail = NULL;
}

leaf_filter *search_filters(leaf_filter_list *list, unsigned char *haystack)
{
	leaf_filter *filter;

	if (!haystack || !*haystack)
		return NULL;

	filter = list->head;
	while (filter) {
		if (leaf_strstr((const char *)haystack, (const char *)filter->data)) {
			ci_debug_printf(4, "leaf: needle found in search filters -> %s\n", filter->data);
			return filter;
		}
		filter = filter->next;
	}
	ci_debug_printf(4, "leaf: no filters found for -> %s\n", haystack);
	return NULL;
}

void leaf_parse_options_file(void)
{
	char buffer[1024];
	FILE *fp;

	filter_include_list.head = filter_include_list.tail = NULL;
	filter_exclude_list.head = filter_exclude_list.tail = NULL;

	leaf_parse_mysql_file();

	fp = fopen("/etc/c-icap/leaf.conf", "rb");

	while (fp && !feof(fp))
	{
		if (fgets(buffer, 1024, fp)) 
		{
			int count;
			char temp[1024], *src, *dest;
			temp[0] = '\0';
			count = 0;
			src = buffer;
			dest = temp;

			// strip out all spaces and punc characters
			while (*src) {
				if (++count > 1024)
					break;
				if ((*src == '\n') || (*src == ' ') || (*src == '\t') ||
					 (*src == '\r') || (*src == ';') || (*src == ',')) {
					src++;
				}
				else				
					*dest++ = *src++;
			}
			*dest = '\0';

			// skip empty lines
			if (!temp[0])
				continue;

			// skip comments
			if (!strncasecmp(temp, "#", 1))
				continue;

			if (!strncasecmp(temp, "db_host=", 8)) {
				strncpy(db_host, &temp[8], MAX_SQL_HOSTNAME);
				db_host[MAX_SQL_HOSTNAME] = '\0';
			}
			else if (!strncasecmp(temp, "db_name=", 8)) {
				strncpy(db_name, &temp[8], MAX_SQL_DATABASE_NAME);
				db_name[MAX_SQL_DATABASE_NAME] = '\0';
			}
			else if (!strncasecmp(temp, "db_table=", 9)) {
				strncpy(db_table, &temp[9], MAX_SQL_TABLE_NAME);
				db_table[MAX_SQL_TABLE_NAME] = '\0';
			}
			else if (!strncasecmp(temp, "db_user=", 8)) {
				strncpy(db_user, &temp[8], MAX_SQL_USER_NAME);
				db_user[MAX_SQL_USER_NAME] = '\0';
			}
			else if (!strncasecmp(temp, "db_pass=", 8)) {
				strncpy(db_pass, &temp[8], MAX_SQL_PASSWORD);
				db_pass[MAX_SQL_PASSWORD] = '\0';
			}
			else if (!strncasecmp(temp, "db_path=", 8)) {
				strncpy(db_path, &temp[8], MAX_PATH_LENGTH);
				db_path[MAX_PATH_LENGTH] = '\0';
			}
#if 0
			else if (!strncasecmp(temp, "db_init_on_startup=", 19)) {
				db_init_startup = atoi(&temp[19]);
			}
#endif
			else if (!strncasecmp(temp, "db_mode=", 8)) {
				db_mode = atoi(&temp[8]);
			}
			else if (!strncasecmp(temp, "db_max_size=", 12)) {
				db_max_size = atoi(&temp[12]);
			}
			else if (!strncasecmp(temp, "skip_length=", 12)) {
				skip_length = atoi(&temp[12]);
			}
			else if (!strncasecmp(temp, "condensed_max_length=", 21)) {
				condensed_max_length = atoi(&temp[21]);
			}
			else if (!strncasecmp(temp, "show_skipped_requests=", 22)) {
				show_skipped_requests = atoi(&temp[22]);
			}
			else if (!strncasecmp(temp, "db_free_space_threshold=", 24)) {
				db_free_space_threshold = atol(&temp[24]);
			}
			else if (!strncasecmp(temp, "leaf_bypass=", 12)) {
				leaf_bypass = atoi(&temp[12]);
			}
			else if (!strncasecmp(temp, "mysql_bypass=", 13)) {
				mysql_bypass = atoi(&temp[13]);
			}
			else if (!strncasecmp(temp, "db_queue_depth=", 15)) {
				db_queue_depth = atoi(&temp[15]);
				if (!db_queue_depth)
					db_queue_depth = 10;
			}
			else if (!strncasecmp(temp, "db_queue_threads=", 17)) {
				db_queue_threads = atoi(&temp[17]);
				if (db_queue_threads > MAX_QUEUE_THREADS)
					db_queue_threads = MAX_QUEUE_THREADS;
				if (!db_queue_threads)
					db_queue_threads = MIN_QUEUE_THREADS;
			}
			else if (!strncasecmp(temp, "db_queue_mode=", 14)) {
				db_queue_mode = atoi(&temp[14]);
			}
			else if (!strncasecmp(temp, "db_queue_sync=", 14)) {
				db_queue_sync = atoi(&temp[14]);
			}
		}
	}


	if (fp)
		fclose(fp);

	ci_debug_printf(4, "leaf: db_host = %s\n", db_host);
	ci_debug_printf(4, "leaf: db_name = %s\n", db_name);
	ci_debug_printf(4, "leaf: db_table = %s\n", db_table);
	ci_debug_printf(4, "leaf: db_user = %s\n", db_user);
	ci_debug_printf(4, "leaf: db_pass = %s\n", db_pass);
	ci_debug_printf(4, "leaf: db_path = %s\n", db_path);
#if 0
	ci_debug_printf(4, "leaf: db_init_startup = %i\n", db_init_startup);
#endif
	ci_debug_printf(4, "leaf: db_mode = %i\n", db_mode);
	ci_debug_printf(4, "leaf: db_max_size = %ld\n", db_max_size);
	ci_debug_printf(4, "leaf: db_queue_depth = %lu\n", db_queue_depth);
	ci_debug_printf(4, "leaf: db_queue_threads = %lu\n", db_queue_threads);
	ci_debug_printf(4, "leaf: db_queue_mode = %lu\n", db_queue_mode);
	ci_debug_printf(4, "leaf: db_queue_sync = %lu\n", db_queue_sync);
	ci_debug_printf(4, "leaf: skip_length = %ld\n", skip_length);
	ci_debug_printf(4, "leaf: condensed_max_length = %ld\n", condensed_max_length);
	ci_debug_printf(4, "leaf: show_skipped_requests = %i\n", show_skipped_requests);
	ci_debug_printf(4, "leaf: leaf_bypass = %i\n", leaf_bypass);
	ci_debug_printf(4, "leaf: mysql_bypass = %i\n", mysql_bypass);
	ci_debug_printf(4, "leaf: db_free_space_threshold = %llu\n", db_free_space_threshold);
	mysql_free_space = mysql_free_size(db_path);
	ci_debug_printf(4, "leaf: mysql_free_space = %llu\n", mysql_free_space);
}

// 0: searching for < or & (& as in &nbsp; etc),
// 1: searching for >, 
// 2: searching for ; after &, 
// 3: searching for </script>,</style>, -->

int parse_html(char *inbuf, size_t inlen, char *outbuf, size_t outlen)
{
	int i=0,j=0,k=0,html=0,body=0;
	int flag = 0; 
	char tempbuf[1024*1024] = "";
	char searchbuf[1024] =  "";

	if (!inbuf || !inlen)
		return 0;

	while (i < inlen && j < outlen && k < (1024*1024)) 
	{
		if (inbuf[i] == '<') {
			if (!strncasecmp(&inbuf[i], "<html", 5))
			{
				i += 5;
				html++;
				for ( ;i < inlen; ) {
					if (!strncasecmp(&inbuf[i], "/>", 2))
					{
						i += 2;
						if (html)
							html--;
						break;
					}
					else if (!strncasecmp(&inbuf[i], ">", 1))
					{
						i += 1;
						break;
					} else {
						i++;
					}
				}
			}
			else if (!strncasecmp(&inbuf[i], "</html>", 7))
			{
				i += 7;
				if (html)
					html--;
			}
			else if (!strncasecmp(&inbuf[i], "<body", 5))
			{
				i += 5;
				body++;
				for ( ;i < inlen; ) {
					if (!strncasecmp(&inbuf[i], "/>", 2))
					{
						i += 2;
						if (body)
							body--;
						break;
					}
					else if (!strncasecmp(&inbuf[i], ">", 1))
					{
						i += 1;
						break;
					} else {
						i++;
					}
				}
			}
			else if (!strncasecmp(&inbuf[i], "</body>", 7))
			{
				i += 7;
				if (body)
					body--;
			}
		}

		if (flag == 0)
		{
			if (inbuf[i] == '<')
			{
				flag = 1;
				tempbuf[0] = '\0';
				// track for <script>,<style>, <!-- --> etc
				k = 0;
			}
			else if (inbuf[i] == '&')
			{
				flag = 2;
			}
			else
			{
				if (body && html) {
					outbuf[j] = inbuf[i];
					j++;
				}
			}
		}
		else if (flag == 1)
		{
			tempbuf[k] = inbuf[i];
			k++;
			tempbuf[k] = '\0';
#ifdef DEBUG_PARSE_HTML
			ci_debug_printf(4, "DEBUG: %s\n",tempbuf);
#endif
			if ((!strcasecmp(tempbuf,"script")))
			{
				flag = 3;
				strcpy(searchbuf,"</script>");
#ifdef DEBUG_PARSE_HTML
				ci_debug_printf(4, "DEBUG: Detected %s\n",tempbuf);
#endif
				tempbuf[0] = '\0';
				k = 0;
			}
			else if ((!strcasecmp(tempbuf,"style")))
			{
				flag = 3;
				strcpy(searchbuf,"</style>");
#ifdef DEBUG_PARSE_HTML
				ci_debug_printf(4, "DEBUG: Detected %s\n",tempbuf);
#endif
				tempbuf[0] = '\0';
				k = 0;
			}
			else if ((!strcasecmp(tempbuf,"!--")))
			{
				flag = 3;
				strcpy(searchbuf,"-->");
#ifdef DEBUG_PARSE_HTML
				ci_debug_printf(4, "DEBUG: Detected %s\n",tempbuf);
#endif
				tempbuf[0] = '\0';
				k = 0;
			}
               
			if (inbuf[i] == '>')
			{
				if (body && html) {
					outbuf[j] = ' ';
					j++;
				}
				flag = 0;
			}
                
		}
		else if (flag == 2)
		{
			if (inbuf[i] == ';')
			{
				if (body && html) {
					outbuf[j] = ' ';
					j++;
				}
				flag = 0;
			}
		}
		else if (flag == 3)
		{
			tempbuf[k] = inbuf[i];
			k++;
			tempbuf[k] = '\0';
#ifdef DEBUG_PARSE_HTML
			ci_debug_printf(4, "DEBUG: %s\n",tempbuf);
			ci_debug_printf(4, "DEBUG: Searching for %s\n",searchbuf);
#endif
			if (!strcasecmp(&tempbuf[0] + k - strlen(searchbuf), searchbuf))
			{
				flag = 0;
#ifdef DEBUG_PARSE_HTML
				ci_debug_printf(4, "DEBUG: Detected END OF %s\n",searchbuf);
#endif
				searchbuf[0] = '\0';
				tempbuf[0] = '\0';
				k = 0;
			}
		}
		i++;
	}
	outbuf[j] = '\0';
	return j;
}

int trim(char *str)
{
	char *end;

	// Trim leading space
	while (isspace((unsigned char)*str)) str++;

	if (*str == 0)  // All spaces?
		return 0;

	// Trim trailing space
	end = str + strlen(str) - 1;
	while (end > str && isspace((unsigned char)*end)) end--;

	// Write new null terminator character
	end[1] = '\0';

	return (int)(end - str);
}

int leaf_lock(void)
{
	if (!mutex_sem)
		return -EINVAL;
	if (sem_wait(mutex_sem) == -1)
		return -EINTR;
	return 0;
}

int leaf_unlock(void)
{
	if (!mutex_sem)
		return -EINVAL;
	if (sem_post(mutex_sem) == -1)
		return -EINTR;
	return 0;
}

void init_maps(void) 
{
	// set umask to 000
    	umask(0);

	stats_fd = mmap(NULL, sizeof *stats_fd, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (stats_fd == (void *)-1) {
		stats_fd = NULL;
		ci_debug_printf(4, "leaf: mmap failed pid %ld\n", (unsigned long) getpid());
	}
	else { 
		ci_debug_printf(4, "leaf: mmap success %p pid %ld\n", stats_fd, (unsigned long) getpid());
	}

	if ((stats_shm = shm_open(STATS_MEM_NAME, O_RDWR | O_CREAT, 0644)) == -1) {
		stats_shm = 0;
		ci_debug_printf(4, "leaf: shm_open %s failed pid %ld\n", STATS_MEM_NAME, (unsigned long) getpid());
	}
	else {
		ci_debug_printf(4, "leaf: shm_open %s success %i pid %ld\n", STATS_MEM_NAME, stats_shm, (unsigned long) getpid());
	}
	if (stats_fd) 
		*stats_fd = stats_shm;

	if (ftruncate(stats_shm, sizeof(global)) == -1) {
		ci_debug_printf(4, "leaf: ftruncate failed pid %ld\n", (unsigned long) getpid());
	}
	else { 
		ci_debug_printf(4, "leaf: ftruncate size set to %ld pid %ld\n", sizeof(global), (unsigned long) getpid());	
	}

	if (stats_shm > 0) {
		if ((stats_ptr = mmap(NULL, sizeof(global), PROT_READ | PROT_WRITE, MAP_SHARED, stats_shm, 0)) == MAP_FAILED) {
			ci_debug_printf(4, "leaf: mmap failed %p pid %ld\n", stats_ptr, (unsigned long) getpid());
			stats_ptr = NULL;
		}
		else {
			ci_debug_printf(4, "leaf: mmap success %p pid %ld\n", stats_ptr, (unsigned long) getpid());
		}
	}	

	if ((mutex_sem = sem_open(SEM_MUTEX_NAME, O_CREAT, 0666, 1)) == SEM_FAILED) {
		ci_debug_printf(4, "leaf: sem_open %s failed %p pid %ld\n", SEM_MUTEX_NAME, mutex_sem, (unsigned long) getpid());
		mutex_sem = NULL;
	}
	else {
		ci_debug_printf(4, "leaf: sem_open %s %p pid %ld\n", SEM_MUTEX_NAME, mutex_sem, (unsigned long) getpid());
	}
}

void close_maps(void) 
{
	if (mutex_sem) {
		if (!sem_close(mutex_sem)) {
			ci_debug_printf(4, "leaf: sem_close %p pid %ld\n", mutex_sem, (unsigned long) getpid());
		}
		else {
			ci_debug_printf(4, "leaf: sem_close failed %p pid %ld\n", mutex_sem, (unsigned long) getpid());
		}

		if (!sem_unlink(SEM_MUTEX_NAME)) {
			ci_debug_printf(4, "leaf: sem_unlink %s pid %ld\n", SEM_MUTEX_NAME, (unsigned long) getpid());
		}
		else {
			ci_debug_printf(4, "leaf: sem_unlink failed %s pid %ld\n", SEM_MUTEX_NAME, (unsigned long) getpid());
		}
		mutex_sem = NULL;
	}

	if (stats_ptr) {
		if (munmap(stats_ptr, sizeof(global))) {
			ci_debug_printf(4, "leaf: munmap failed %p pid %ld\n", stats_ptr, (unsigned long) getpid());
		}
		else {
			ci_debug_printf(4, "leaf: munmap success %p pid %ld\n", stats_ptr, (unsigned long) getpid());
		}
		stats_ptr = NULL;
	}

	if (stats_fd && *stats_fd) {
		if ((shm_unlink(STATS_MEM_NAME)) == -1) {
			ci_debug_printf(4, "leaf: shm_unlink failed %s pid %ld\n", STATS_MEM_NAME, (unsigned long) getpid());
		}
		else {
			ci_debug_printf(4, "leaf: shm_unlink success %s pid %ld\n", STATS_MEM_NAME, (unsigned long) getpid());
			stats_shm = 0;
			*stats_fd = 0;
		}
	}

	if (stats_fd) {
		if (munmap(stats_fd, sizeof *stats_fd)) {
			ci_debug_printf(4, "leaf: munmap failed %p pid %ld\n", stats_fd, (unsigned long) getpid());
		}
		else {
			ci_debug_printf(4, "leaf: munmap success %p pid %ld\n", stats_fd, (unsigned long) getpid());
		}
		stats_fd = NULL;
	}
}

void child_open_maps(void)
{
	if ((stats_shm = shm_open(STATS_MEM_NAME, O_RDWR, 0)) == -1) {
		ci_debug_printf(4, "leaf: shm_open failed pid %ld\n", (unsigned long) getpid());
	}
	else {
		ci_debug_printf(4, "leaf: shm_open %s pid %ld\n", STATS_MEM_NAME, (unsigned long) getpid());
	}

	if (stats_shm > 0) {
		if ((stats_ptr = mmap(NULL, sizeof(global), PROT_READ | PROT_WRITE, MAP_SHARED, stats_shm, 0)) == MAP_FAILED)
		{
			ci_debug_printf(4, "leaf: mmap failed pid %ld\n", (unsigned long) getpid());
			stats_ptr = NULL;
		}
		else {
			ci_debug_printf(4, "leaf: mmap pid %ld addr %p\n", (unsigned long) getpid(), stats_ptr);
		}
	}

	if ((mutex_sem = sem_open(SEM_MUTEX_NAME, 0, 0, 0)) == SEM_FAILED) {
		ci_debug_printf(4, "leaf: sem_open %s %p failed pid %ld\n", SEM_MUTEX_NAME, mutex_sem, (unsigned long) getpid());
		mutex_sem = NULL;
	}
	else {
		ci_debug_printf(4, "leaf: sem_open %s %p pid %ld\n", SEM_MUTEX_NAME, mutex_sem, (unsigned long) getpid());
	}
}

void child_close_maps(void)
{
	if (stats_ptr)
	{
		if (munmap(stats_ptr, sizeof(global)) == -1) {
			ci_debug_printf(4, "leaf: munmap failed pid %ld\n", (unsigned long) getpid());
		}
		else {
			ci_debug_printf(4, "leaf: munmap pid %ld addr %p\n", (unsigned long) getpid(), stats_ptr);
		}
		stats_ptr = NULL;
	}

	if (stats_shm > 0) {
		ci_debug_printf(4, "leaf: shm_close handle (%i) pid %ld\n", stats_shm, (unsigned long) getpid());
		close(stats_shm);
		stats_shm = 0;
	}

	if (mutex_sem) {
		if (!sem_close(mutex_sem)) {
			ci_debug_printf(4, "leaf: sem_close %p pid %ld\n", mutex_sem, (unsigned long) getpid());
		}
		else {
			ci_debug_printf(4, "leaf: sem_close failed %p pid %ld\n", mutex_sem, (unsigned long) getpid());
		}
		mutex_sem = NULL;
	}

}

void bypass_stats(size_t size)
{
	if (stats_ptr) {
		stats_ptr->stats.total.skipped++;
		stats_ptr->stats.total.pages++;
		stats_ptr->stats.total.bytes += size;
	}
}

#define QUARTERSEC 250000
#define ATTEMPTS 12

pthread_t threads[MAX_QUEUE_THREADS];
pthread_mutex_t queue_mutex;
pthread_cond_t queue_cond;
sem_t queue_count;
leaf_queue_list leaf_list;
int depth;
int num_threads, active_threads;
int thread_active[MAX_QUEUE_THREADS];

leaf_queue_list fill_list;
pthread_mutex_t fill_mutex;
int fill_depth;
int fill_thread_active;
int active_fill_threads;

int get_count(leaf_queue_list *list) 
{
	register int j = 0;
	leaf_queue *node = list->head;
	
	while (node) {
		j++;
		node = node->next;
	}
	return j;
}

leaf_queue *get_node(leaf_queue_list *list)
{
	leaf_queue *node;
	
	if (list->head)
	{
		node = list->head;
		list->head = node->next;
		if (list->head)
			list->head->prior = NULL;
		else
			list->tail = NULL;
		node->next = node->prior = NULL;
		return node;
	}
	return NULL;
}


leaf_queue *add_node(leaf_queue *node, leaf_queue_list *list)
{
	if (!list->head)
	{
		list->head = node;
		list->tail = node;
		node->next = node->prior = NULL;
	}
	else
	{
		list->tail->next = node;
		node->next = NULL;
		node->prior = list->tail;
		list->tail = node;
	}
	return node;
}

void free_nodes(leaf_queue_list *list)
{
	leaf_queue *node;

	while (list->head) {
		node = list->head;
		list->head = node->next;
		free(node);
		depth--;
	}
	list->head = list->tail = NULL;
}

int leaf_query(leaf_queue *query)
{
	char buf[1024];

	if (!query->con) 
	{
		if (stats_ptr) {
			stats_ptr->stats.total.connection++;
			stats_ptr->stats.total.dropped++;
			stats_ptr->stats.total.errors++;
		}
		return 0;
	}

	if (!mysql_real_query(query->con, query->data, query->len)) {
		if (stats_ptr) {
			stats_ptr->stats.total.pages++;
			stats_ptr->stats.total.bytes += query->len;
		}
		ci_debug_printf(4, "leaf: mysql query written length is %llu\n", query->len);
	}
	else {
		ci_debug_printf(4, "leaf: mysql returned errno %i -> %s\n", mysql_errno(query->con), mysql_error(query->con));
		switch (mysql_errno(query->con)) {
		case ER_PARSE_ERROR:
			snprintf(buf, sizeof(buf), "leaf: mysql returned errno %i -> %s\n", mysql_errno(query->con), mysql_error(query->con));
			leaf_store_log(buf, strlen(buf));
			leaf_store_log(query->data, query->len);
			if (stats_ptr) {
				stats_ptr->stats.total.process++;
				stats_ptr->stats.total.dropped++;
				stats_ptr->stats.total.errors++;
			}
			break;
		case CR_SERVER_LOST:
		case CR_SERVER_GONE_ERROR:
			snprintf(buf, sizeof(buf), "leaf: mysql returned errno %i -> %s\n", mysql_errno(query->con), mysql_error(query->con));
			leaf_store_log(buf, strlen(buf));
			query->con = leaf_close(query->con);
			query->con = leaf_connect(db_name); 
			// retry query if connection went away 
			if (query->con && !mysql_real_query(query->con, query->data, query->len)) {
				if (stats_ptr) {
					stats_ptr->stats.total.pages++;
					stats_ptr->stats.total.bytes += query->len;
				}
				ci_debug_printf(4, "leaf: mysql query retry written length is %llu\n", query->len);
			}
			else {
				if (stats_ptr) {
					stats_ptr->stats.total.connection++;
					stats_ptr->stats.total.dropped++;
					stats_ptr->stats.total.errors++;
				}
			}
			break;
		default:
			snprintf(buf, sizeof(buf), "leaf: mysql returned errno %i -> %s\n", mysql_errno(query->con), mysql_error(query->con));
			leaf_store_log(buf, strlen(buf));
			// close connection if content errors
			query->con = leaf_close(query->con);
			if (stats_ptr) {
				stats_ptr->stats.total.process++;
				stats_ptr->stats.total.dropped++;
				stats_ptr->stats.total.errors++;
			}
			break;
		}
	} 
	return 0;
}

void *fill_thread(void *p)
{
	ci_debug_printf(4, "leaf: pid %ld fill thread started\n", (unsigned long)getpid());

	pthread_mutex_lock(&fill_mutex);
	active_fill_threads++;
	pthread_mutex_unlock(&fill_mutex);

	while (fill_thread_active)
	{
		if (usleep(QUARTERSEC))
			break;
	}

	pthread_mutex_lock(&fill_mutex);
	active_fill_threads--;
	pthread_mutex_unlock(&fill_mutex);

	ci_debug_printf(4, "leaf: pid %ld fill thread exited\n", (unsigned long)getpid());
	pthread_exit(0);
	return NULL;
}

void *async_thread(void *p)
{
	register unsigned long i = (unsigned long)p;
	leaf_queue *node;
	MYSQL *conn;

	//ci_debug_printf(4, "leaf: mysql pthread %lu pid: %ld\n", i, (unsigned long)getpid());

	pthread_mutex_lock(&queue_mutex);
	active_threads++;
	pthread_mutex_unlock(&queue_mutex);

        conn = leaf_connect(db_name); 

	while (thread_active[i])
	{
		pthread_mutex_lock(&queue_mutex);
		while (!leaf_list.head) {
			pthread_cond_wait(&queue_cond, &queue_mutex);
			if (!thread_active[i])
				break;
		}
		node = get_node(&leaf_list);
		if (node)
			depth--;
		pthread_mutex_unlock(&queue_mutex);

		if (node) {
			if (!conn)
	        		conn = leaf_connect(db_name); 

			if (conn) {
				node->con = conn;
				leaf_query(node);
				conn = node->con;
			}
			else {
				if (stats_ptr) {
					stats_ptr->stats.total.connection++;
					stats_ptr->stats.total.dropped++;
					stats_ptr->stats.total.errors++;
				}
			}
			free(node);
			sem_post(&queue_count);
		}
	}
        conn = leaf_close(conn); 

	pthread_mutex_lock(&queue_mutex);
	active_threads--;
	pthread_mutex_unlock(&queue_mutex);

	//ci_debug_printf(4, "leaf: pthread %lu exiting pid: %ld\n", i, (unsigned long)getpid());
	pthread_exit(0);
	return NULL;
}


void close_threads(void)
{
	register unsigned long i;

	if (!num_threads) 
		return;

	for (i=0; i < db_queue_threads; i++) 
		thread_active[i] = 0;
	i = 0;
	while (active_threads) {
		pthread_cond_broadcast(&queue_cond);
		if (usleep(QUARTERSEC))
			break;
		if (i++ > ATTEMPTS)
			break;
	}

	i = 0;
	fill_thread_active = 0;
	while (active_fill_threads) {
		if (usleep(QUARTERSEC))
			break;
		if (i++ > ATTEMPTS)
			break;
	}

	pthread_mutex_lock(&queue_mutex);
	free_nodes(&leaf_list);
	pthread_mutex_unlock(&queue_mutex);

	pthread_cond_destroy(&queue_cond);
	sem_destroy(&queue_count);
	pthread_mutex_destroy(&queue_mutex);
	pthread_mutex_destroy(&fill_mutex);
	num_threads = 0;
	depth = 0;
	fill_depth = 0;

}

int start_threads(void)
{
	register unsigned long i;

	if (!num_threads) {
		sem_init(&queue_count, 0, db_queue_depth);
		leaf_list.head = leaf_list.tail = NULL;
		fill_list.head = fill_list.tail = NULL;
		pthread_mutex_init(&queue_mutex, NULL);
		pthread_mutex_init(&fill_mutex, NULL);
		pthread_cond_init(&queue_cond, NULL);
		for (i=0; i < db_queue_threads; i++) {
			thread_active[i] = 1;
			pthread_create(&threads[i], NULL, async_thread, (void *)i);
			num_threads++;
		}
		fill_thread_active = 1;
		pthread_create(&threads[i], NULL, fill_thread, (void *)0);
	}
	return num_threads;
}

int leaf_queue_query(leaf_queue *node)
{
	if (!num_threads)
		start_threads();

	if (mysql_bypass) {
		if (stats_ptr) {
			stats_ptr->stats.total.skipped++;
			stats_ptr->stats.total.pages++;
			stats_ptr->stats.total.bytes += node->len;
		}
		free(node);
		return 0;
	}

	if (db_queue_mode) {
		if (sem_trywait(&queue_count)) {
			if (stats_ptr) {
				stats_ptr->stats.total.queue++;
				stats_ptr->stats.total.dropped++;
				stats_ptr->stats.total.errors++;
			}
			free(node);
			return 0;
		}
	}
	else {
		if (sem_wait(&queue_count)) {
			if (stats_ptr) {
				stats_ptr->stats.total.queue++;
				stats_ptr->stats.total.dropped++;
				stats_ptr->stats.total.errors++;
			}
			free(node);
			return 0;
		}
	}

	pthread_mutex_lock(&queue_mutex);
	add_node(node, &leaf_list);
	depth++;
	pthread_cond_signal(&queue_cond);
	pthread_mutex_unlock(&queue_mutex);
	return 0;
}

int leaf_store_common(char *inbuf, size_t inlen, char *url, size_t ulen,
                      char *request, size_t reqlen, char *response, size_t reslen,
                      char *ip, int ilen, char *account, int alen, char *host,
		      int hostlen, int whitelist)
{
        if (!inlen)
        {
           ci_debug_printf(4, "leaf: leafstore inlen was 0, skipping request\n");
	   return 0;
        }
#if 0
        if (!db_active)
        {
           ci_debug_printf(4, "leaf: database is offline, skipping request\n");
	   return 0;
        }
#endif
	struct _html_data {
		char *data;
		size_t size;
	} html_data[10];

	html_data[0].data = url;	// url
	html_data[0].size = ulen;	// url length
	html_data[1].data = NULL;	// title
	html_data[1].size = 0;		// title length
	html_data[2].data = request;	// http request headers
	html_data[2].size = reqlen;	// http request headers length
	html_data[3].data = response;	// http response headers
	html_data[3].size = reslen;	// http response headers length
	html_data[4].data = account;	// account 
	html_data[4].size = alen;	// account length
	html_data[5].data = ip;		// client IP 
	html_data[5].size = ilen;	// client IP length
	html_data[6].data = NULL;	// pagetext
	html_data[6].size = 0;		// pagetext length
	html_data[7].data = NULL;	// condensed pagetext
	html_data[7].size = 0;		// condensed pagetext length	
	html_data[8].data = inbuf;	// page entry
	html_data[8].size = inlen;	// page length (uncompressed)
	html_data[9].data = host;	// host IP 
	html_data[9].size = hostlen;	// host IP length

	char *localip = "127.0.0.1";
	int locallen = strlen(localip);
	if (!ilen) {
		html_data[5].data = localip;	// client IP 
		html_data[5].size = locallen;	// client IP length
	}

#if 0
        ci_debug_printf(4, "leaf: ip was [%s] length %d strlen %d\n", ip, ilen, (int)strlen(ip));
        ci_debug_printf(4, "leaf: acct was [%s] length %d strlen %d\n", account, alen, (int)strlen(account));
        ci_debug_printf(4, "leaf: url was length %d strlen %d\n", (int)ulen, (int)strlen(url));
        ci_debug_printf(4, "leaf: inbuf was length %d strlen %d\n", (int)inlen, (int)strlen(inbuf));
        ci_debug_printf(4, "leaf: req was length %d strlen %d\n", (int)reqlen, (int)strlen(request));
        ci_debug_printf(4, "leaf: resp was length %d strlen %d\n", (int)reslen, (int)strlen(response));
#endif
	char       *title = NULL; 
	char       *title_pattern = "<title[^>]*>(.+?)</title>"; 
	regex_t    title_preg;
	regmatch_t title_pmatch[2];

	size_t     nmatch = 2;
	int        rc;

	// extract the title field from the head html text section 
	if (!(rc = regcomp(&title_preg, title_pattern, REG_EXTENDED | REG_ICASE))) {
		if (!(rc = regexec(&title_preg, inbuf, nmatch, title_pmatch, 0))) {
	                title = malloc(title_pmatch[1].rm_eo - title_pmatch[1].rm_so + 1);
			if (title) {
				int slen = title_pmatch[1].rm_eo - title_pmatch[1].rm_so;
				int i, tlen = slen;
				char *s = &inbuf[title_pmatch[1].rm_so], *d = title;

				// GNU regex will match the last search tag from the end 
				// of the search text instead of the first ending tag encountered.
				// We have to search for a title end tag for any page which 
				// contains more than one set of title tags <title>...</title>
				// in a single head section. 

				for (i = 0; *s && i < slen; i++) {
					if (!strncasecmp(s, "</title>", 8)) {
						tlen = i;
						break;
					}
					*d++ = *s++;
				}
				*d = '\0';

				// Microsoft browsers (IE and Edge) set the limit to 512 bytes
				// for an html title field.
				if (tlen > MAX_HTML_TITLE) {
					tlen = MAX_HTML_TITLE;
				}	title[tlen] = '\0';

				html_data[1].data = title;
				html_data[1].size = tlen;
	        		ci_debug_printf(4, "leaf: title search returned size of %i bytes [%s]\n", tlen, title);
#if 0
                                ci_debug_printf(4, "leaf: title was length %d strlen %d\n", tlen, (int)strlen(title));
#endif
			}
		}
		regfree(&title_preg);
	}

	char *condensed = NULL;
	int clen = 0, maxlen = 0;

        if (condensed_max_length) {
		condensed = malloc(condensed_max_length + 1);
		maxlen = condensed_max_length;
	}
	else {
		condensed = malloc(inlen + 1);
		maxlen = inlen;
	}
	if (condensed) {
		clen = parse_html(inbuf, inlen, condensed, maxlen);
		if (!whitelist && (clen < skip_length)) {
			ci_debug_printf(4, "leaf: pagetext size was %i bytes, skip_len is %lu, skipping request\n", clen, skip_length);
			if (title)
				free(title);
			if (condensed)
				free(condensed);
			if (stats_ptr) {
				stats_ptr->stats.total.skipped++;
			}
			return 0;
		}
		ci_debug_printf(4, "leaf: parse_html returned size of %i\n", clen);
		html_data[7].data = condensed; 
		html_data[7].size = clen; 
	}

	char st1_start[MAX_SQL_TABLE_NAME+1024+1];
	st1_start[0] = '\0';
	char *st1_start_fmt = "INSERT INTO %s(url,title,request,response,account,ip,pagetext,condensed,page,host,create_date,last_modified_date) VALUES(";
	int st1_start_len = snprintf(st1_start, 1024, st1_start_fmt, db_table) + 1;
	char *st1_end = "now(),now())";
	int st1_end_len = strlen(st1_end) + 1;
	int st1_len = st1_start_len + st1_end_len;
	char *st1_empty = "'',";
	int st1_empty_len = strlen(st1_empty) + 1;

	char *st2_start = ",(";
	char *st2_end = "now(),now())";
	int st2_start_len = strlen(st2_start) + 1;
	int st2_end_len = strlen(st2_end) + 1;
	int st2_len = st2_start_len + st2_end_len;
        if (st2_len) {};
	char *ut1_start = "UPDATE %s SET url='%s',title='%s',request='%s',response='%s',account='%s',ip='%s',pagetext='%s',condensed='%s',"
                            "page='%s', host='%s', create_date=now(),last_modified_date=now() WHERE id='%lu'";
	int ut1_len = strlen(ut1_start);
        if (ut1_len) {};
	register int i;
	register unsigned long len = 0;
	
        if (!con) {
        	if (!con)
			con = leaf_connect(NULL); 
	}
		
	if (con) {
		unsigned long total = st1_len;
		for (i=0; i < 10; i++) {
		   if (html_data[i].size)
		      total += (html_data[i].size + 1) * 2;
		   total += st1_empty_len;
		}
		ci_debug_printf(4, "leaf: query allocation size %lu pid %ld\n", total + sizeof(leaf_queue), (unsigned long) getpid());

		leaf_queue *query = malloc(total + sizeof(leaf_queue));
		if (query)
		{                 
			// start of query
			len += snprintf(&query->data[len], st1_start_len, "%s", st1_start);
			for (i=0; i < 10; i++) {
				int size = html_data[i].size;
				unsigned long eret;
				char *data = html_data[i].data;
				if (!size || !data) {
					len += snprintf(&query->data[len], st1_empty_len, "%s", st1_empty);
					continue;
				}
				len += snprintf(&query->data[len], 2, "'");
				eret = mysql_real_escape_string(con, &query->data[len], data, size);
				if (eret == (unsigned long)-1)	{
					stats_ptr->stats.total.process++;
					stats_ptr->stats.total.errors++;

					ci_debug_printf(4, "leaf: mysql_real_escape_string error pid %ld\n", (unsigned long) getpid());
				}
				else {
					len += eret;
				}
				len += snprintf(&query->data[len], 3, "',");
			}
			// end of query
			len += snprintf(&query->data[len], st1_end_len, "%s", st1_end);
			if (len) {
				// realloc to adjust memory to final size 
				leaf_queue *newquery = realloc(query, len + sizeof(leaf_queue));
				if (newquery) {
					ci_debug_printf(4, "leaf: realloc query memory from %lu -> %lu\n",
							total + sizeof(leaf_queue), len + sizeof(leaf_queue));
					query = newquery;
				}
				query->len = len;
				if (db_queue_sync) {
					query->con = leaf_connect(db_name); 
					leaf_query(query);
					if (query->con)
						query->con = leaf_close(query->con);
	 				free(query);
				} 
				else {
					query->con = NULL;
					leaf_queue_query(query);
				}
			}
			else {
	 			free(query);
			}
		}
		else {
			if (stats_ptr) {
				stats_ptr->stats.total.allocation++;
				stats_ptr->stats.total.dropped++;
				stats_ptr->stats.total.errors++;
			}
		}
	} 
	else {
		if (stats_ptr) {
			stats_ptr->stats.total.connection++;
			stats_ptr->stats.total.dropped++;
			stats_ptr->stats.total.errors++;
		}
	}
	if (title)
		free(title);
	if (condensed)
		free(condensed);
	return len;
}


int init_database(void *con, int flags)
{
	MYSQL_ROW row;
	MYSQL_RES *result;
	int num_fields;
	unsigned long long max_packet = 0;
	int i, db_present = 0, table_present = 0;
	char sql[MAX_SQL_LENGTH];

	// set max allowed packet to 1GB
	if (mysql_query(con, "SHOW VARIABLES LIKE 'max_allowed_packet'"))
	{
		ci_debug_printf(4, "leaf: %s\n", mysql_error(con));
		return 0;
	}
	
	result = mysql_store_result(con);
	if (result == NULL) {
		ci_debug_printf(4, "leaf: %s\n", mysql_error(con));
		return 0;
	}

	num_fields = mysql_num_fields(result);
	row = mysql_fetch_row(result); 
	if (num_fields > 1 && row[1])
		max_packet = atoll(row[1]);
	ci_debug_printf(4, "leaf: max_allowed_packet is %llu\n", max_packet); 
	mysql_free_result(result);

	if (max_packet < 1073741824) {
		ci_debug_printf(4, "leaf: set max_allowed_packet from %llu to 1073741824\n", max_packet); 
		if (mysql_query(con, "SET GLOBAL max_allowed_packet=1073741824")) {
			ci_debug_printf(4, "leaf: %s\n", mysql_error(con));
			return 0;
		}
	}

	if (flags) {
		// reinit and drop current database if directed to do so
		snprintf(sql, MAX_SQL_LENGTH, "DROP DATABASE IF EXISTS %s", db_name);
		if (mysql_query(con, sql))
		{
			ci_debug_printf(4, "%s\n", mysql_error(con));
			return 0;
		}

		snprintf(sql, MAX_SQL_LENGTH, "CREATE DATABASE %s CHARACTER SET utf8 COLLATE utf8_general_ci", db_name);
		if (mysql_query(con, sql)) 
		{
			ci_debug_printf(4, "%s\n", mysql_error(con));
			return 0;
		}
		ci_debug_printf(4, "leaf: created database '%s'\n", db_name);

		snprintf(sql, MAX_SQL_LENGTH, "USE %s", db_name);
		if (mysql_query(con, sql))
		{
			ci_debug_printf(4, "%s\n", mysql_error(con));
			return 0;
		}

		snprintf(sql, MAX_SQL_LENGTH, "DROP TABLE IF EXISTS %s", db_table);
		if (mysql_query(con, sql))
		{
			ci_debug_printf(4, "%s\n", mysql_error(con));
			return 0;
		}

		snprintf(sql, MAX_SQL_LENGTH,
			"CREATE TABLE `%s` (\
			`id` BIGINT(20) unsigned NOT NULL auto_increment,\
			`clientid` int(10) unsigned default NULL,\
			`deleted` int(10) unsigned default '0',\
			`tagged` int(10) unsigned default '0',\
			`userlist` int(10) unsigned default '0',\
			`create_date` datetime NOT NULL default '0000-00-00 00:00:00',\
			`last_modified_date` datetime NOT NULL default '0000-00-00 00:00:00',\
			`flags` text,\
			`url` text,\
			`page` mediumtext,\
			`language` text,\
			`name` text,\
			`username` text,\
			`account` text,\
			`listname` text,\
			`title` text,\
			`ip` text,\
			`host` text,\
			`request` text,\
			`response` text,\
			`pagetext` mediumtext,\
			`condensed` mediumtext,\
			KEY `create_index` (`create_date`),\
			KEY `title_index` (`title`(333)),\
			KEY `url_index` (`url`(333)),\
			KEY `language_index` (`language`(333)),\
			KEY `pagetext_index` (`pagetext`(333)),\
			KEY `cond_index` (`condensed`(333)),\
			KEY `ip_index` (`ip`(333)),\
			KEY `host_index` (`host`(333)),\
			KEY `account_index` (`account`(333)),\
			FULLTEXT KEY `titlesearch` (`title`),\
			FULLTEXT KEY `condsearch` (`condensed`),\
			PRIMARY KEY  (`id`)\
			) ENGINE=MYISAM DEFAULT CHARSET=utf8mb4 AUTO_INCREMENT=1;", db_table);
		if (mysql_query(con, sql))
		{
			ci_debug_printf(4, "%s\n", mysql_error(con));
			return 0;
		}
		ci_debug_printf(4, "leaf: created database table '%s'\n", db_table);
		return 1;
	}


	// check if database exists
	snprintf(sql, MAX_SQL_LENGTH, "SHOW DATABASES like '%s'", db_name);
	if (mysql_query(con, sql)) 
	{
		ci_debug_printf(4, "leaf: %s\n", mysql_error(con));
		return 0;
	}
	result = mysql_store_result(con);
	if (result == NULL) 
	{
		ci_debug_printf(4, "leaf: %s\n", mysql_error(con));
		return 0;
	}
	num_fields = mysql_num_fields(result);
	while ((row = mysql_fetch_row(result))) 
	{ 
		for (i = 0; i < num_fields; i++) 
		{ 
			if (!strcasecmp(row[i], db_name)) {
				ci_debug_printf(4, "leaf: database \"%s\" present\n", row[i] ? row[i] : "NULL"); 
				db_present = 1;
			}
		} 
	}
	mysql_free_result(result);

	if (!db_present) {
		// reinit and drop current database if directed to do so
		snprintf(sql, MAX_SQL_LENGTH, "DROP DATABASE IF EXISTS %s", db_name);
		if (mysql_query(con, sql))
		{
			ci_debug_printf(4, "%s\n", mysql_error(con));
			return 0;
		}

		snprintf(sql, MAX_SQL_LENGTH, "CREATE DATABASE %s CHARACTER SET utf8 COLLATE utf8_general_ci", db_name);
		if (mysql_query(con, sql)) 
		{
			ci_debug_printf(4, "%s\n", mysql_error(con));
			return 0;
		}
		db_present = 1;
		ci_debug_printf(4, "leaf: created database '%s'\n", db_name);
	}

	if (!db_present) {
		ci_debug_printf(4, "leaf: database 'leafpage' not present\n");
		return 0;
	}

	if (db_present) {
		// select leafpage database 
		snprintf(sql, MAX_SQL_LENGTH, "USE %s", db_name);
		if (mysql_query(con, sql))
		{
			ci_debug_printf(4, "%s\n", mysql_error(con));
			return 0;
		}

		// check if table exists
		snprintf(sql, MAX_SQL_LENGTH, "SHOW TABLES like '%s'", db_table);
		if (mysql_query(con, sql)) 
		{
			ci_debug_printf(4, "leaf: %s\n", mysql_error(con));
			return 0;
		}
		result = mysql_store_result(con);
		if (result == NULL) 
		{
			ci_debug_printf(4, "leaf: %s\n", mysql_error(con));
			return 0;
		}
		num_fields = mysql_num_fields(result);
		while ((row = mysql_fetch_row(result))) 
		{ 
			for (i = 0; i < num_fields; i++) 
			{ 
				if (!strcasecmp(row[i], db_table)) {
					ci_debug_printf(4, "leaf: table \"%s\" present\n", row[i] ? row[i] : "NULL"); 
					table_present = 1;
				}
			} 
		}
		mysql_free_result(result);

		if (!table_present) {
			snprintf(sql, MAX_SQL_LENGTH, "DROP TABLE IF EXISTS %s", db_table);
			if (mysql_query(con, sql))
			{
				ci_debug_printf(4, "%s\n", mysql_error(con));
				return 0;
			}

			snprintf(sql, MAX_SQL_LENGTH,
				"CREATE TABLE `%s` (\
				`id` BIGINT(20) unsigned NOT NULL auto_increment,\
				`clientid` int(10) unsigned default NULL,\
				`deleted` int(10) unsigned default '0',\
				`tagged` int(10) unsigned default '0',\
				`userlist` int(10) unsigned default '0',\
				`create_date` datetime NOT NULL default '0000-00-00 00:00:00',\
				`last_modified_date` datetime NOT NULL default '0000-00-00 00:00:00',\
				`flags` text,\
				`url` text,\
				`page` mediumtext,\
				`language` text,\
				`name` text,\
				`username` text,\
				`account` text,\
				`listname` text,\
				`title` text,\
				`ip` text,\
				`host` text,\
				`request` text,\
				`response` text,\
				`pagetext` mediumtext,\
				`condensed` mediumtext,\
				KEY `create_index` (`create_date`),\
				KEY `title_index` (`title`(333)),\
				KEY `url_index` (`url`(333)),\
				KEY `language_index` (`language`(333)),\
				KEY `pagetext_index` (`pagetext`(333)),\
				KEY `cond_index` (`condensed`(333)),\
				KEY `ip_index` (`ip`(333)),\
				KEY `host_index` (`host`(333)),\
				KEY `account_index` (`account`(333)),\
				FULLTEXT KEY `titlesearch` (`title`),\
				FULLTEXT KEY `condsearch` (`condensed`),\
				PRIMARY KEY  (`id`)\
				) ENGINE=MYISAM DEFAULT CHARSET=utf8mb4 AUTO_INCREMENT=1;", db_table);
			if (mysql_query(con, sql))
			{
				ci_debug_printf(4, "%s\n", mysql_error(con));
				return 0;
			}
			ci_debug_printf(4, "leaf: created database table '%s'\n", db_table);
		}
	}
	return 1;
}

unsigned long long seconds;
unsigned long long average;

void init_stats(void)
{
	if (stats_ptr) {
		stats_ptr->peak_pages_per_second = 0;
		stats_ptr->peak_bytes_per_second = 0;
		stats_ptr->peak_errors_per_second = 0;
		stats_ptr->peak_dropped_per_second = 0;
		stats_ptr->peak_aborts_per_second = 0;
		stats_ptr->peak_skipped_per_second = 0;

		stats_ptr->avg_pages_per_second = 0;
		stats_ptr->avg_bytes_per_second = 0;
		stats_ptr->avg_errors_per_second = 0;
		stats_ptr->avg_dropped_per_second = 0;
		stats_ptr->avg_aborts_per_second = 0;
		stats_ptr->avg_skipped_per_second = 0;

		stats_ptr->pages_per_second = 0;
		stats_ptr->bytes_per_second = 0;
		stats_ptr->errors_per_second = 0;
		stats_ptr->dropped_per_second = 0;
		stats_ptr->aborts_per_second = 0;
		stats_ptr->skipped_per_second = 0;

		stats_ptr->total_pages = 0;
		stats_ptr->total_bytes = 0;
		stats_ptr->total_errors = 0;
		stats_ptr->total_dropped = 0;
		stats_ptr->total_aborts = 0;
		stats_ptr->total_skipped = 0;
		stats_ptr->total_allocation = 0;
		stats_ptr->total_process = 0;
		stats_ptr->total_connection = 0;
		stats_ptr->total_queue = 0;
	}
}

void process_stats(void) 
{
	if (stats_ptr) {
		seconds++;

		stats_ptr->pages_per_second = 0;
		stats_ptr->bytes_per_second = 0;
		stats_ptr->errors_per_second = 0;
		stats_ptr->dropped_per_second = 0;
		stats_ptr->aborts_per_second = 0;
		stats_ptr->skipped_per_second = 0;

		stats_ptr->total_pages = 0;
		stats_ptr->total_bytes = 0;
		stats_ptr->total_errors = 0;
		stats_ptr->total_dropped = 0;
		stats_ptr->total_aborts = 0;
		stats_ptr->total_skipped = 0;
		stats_ptr->total_allocation = 0;
		stats_ptr->total_process = 0;
		stats_ptr->total_connection = 0;
		stats_ptr->total_queue = 0;

		stats_ptr->stats.pages_per_second = stats_ptr->stats.total.pages - stats_ptr->stats.current.pages;
		stats_ptr->stats.bytes_per_second = stats_ptr->stats.total.bytes - stats_ptr->stats.current.bytes;
		stats_ptr->stats.errors_per_second = stats_ptr->stats.total.errors - stats_ptr->stats.current.errors;
		stats_ptr->stats.dropped_per_second = stats_ptr->stats.total.dropped - stats_ptr->stats.current.dropped;
		stats_ptr->stats.aborts_per_second = stats_ptr->stats.total.aborts - stats_ptr->stats.current.aborts;
		stats_ptr->stats.skipped_per_second = stats_ptr->stats.total.skipped - stats_ptr->stats.current.skipped;

		stats_ptr->stats.current.pages =  stats_ptr->stats.total.pages; 
		stats_ptr->stats.current.bytes = stats_ptr->stats.total.bytes;
		stats_ptr->stats.current.errors = stats_ptr->stats.total.errors;
		stats_ptr->stats.current.dropped = stats_ptr->stats.total.dropped;
		stats_ptr->stats.current.aborts = stats_ptr->stats.total.aborts;
		stats_ptr->stats.current.skipped = stats_ptr->stats.total.skipped;
		stats_ptr->stats.current.allocation = stats_ptr->stats.total.allocation;
		stats_ptr->stats.current.process = stats_ptr->stats.total.process;
		stats_ptr->stats.current.connection = stats_ptr->stats.total.connection;
		stats_ptr->stats.current.queue = stats_ptr->stats.total.queue;
		
		stats_ptr->pages_per_second += stats_ptr->stats.pages_per_second;
		stats_ptr->bytes_per_second += stats_ptr->stats.bytes_per_second;
		stats_ptr->errors_per_second += stats_ptr->stats.errors_per_second;
		stats_ptr->dropped_per_second += stats_ptr->stats.dropped_per_second;
		stats_ptr->aborts_per_second += stats_ptr->stats.aborts_per_second;
		stats_ptr->skipped_per_second += stats_ptr->stats.skipped_per_second;

		stats_ptr->total_pages += stats_ptr->stats.total.pages;
		stats_ptr->total_bytes += stats_ptr->stats.total.bytes;
		stats_ptr->total_errors += stats_ptr->stats.total.errors;
		stats_ptr->total_dropped += stats_ptr->stats.total.dropped;
		stats_ptr->total_aborts += stats_ptr->stats.total.aborts;
		stats_ptr->total_skipped += stats_ptr->stats.total.skipped;
		stats_ptr->total_allocation += stats_ptr->stats.total.allocation;
		stats_ptr->total_process += stats_ptr->stats.total.process;
		stats_ptr->total_connection += stats_ptr->stats.total.connection;
		stats_ptr->total_queue += stats_ptr->stats.total.queue;

		if (stats_ptr->pages_per_second > stats_ptr->peak_pages_per_second)
			stats_ptr->peak_pages_per_second = stats_ptr->pages_per_second;
		if (stats_ptr->bytes_per_second > stats_ptr->peak_bytes_per_second)
			stats_ptr->peak_bytes_per_second = stats_ptr->bytes_per_second;
		if (stats_ptr->errors_per_second > stats_ptr->peak_errors_per_second)
			stats_ptr->peak_errors_per_second = stats_ptr->errors_per_second;
		if (stats_ptr->dropped_per_second > stats_ptr->peak_dropped_per_second)
			stats_ptr->peak_dropped_per_second = stats_ptr->dropped_per_second;
		if (stats_ptr->aborts_per_second > stats_ptr->peak_aborts_per_second)
			stats_ptr->peak_aborts_per_second = stats_ptr->aborts_per_second;
		if (stats_ptr->skipped_per_second > stats_ptr->peak_skipped_per_second)
			stats_ptr->peak_skipped_per_second = stats_ptr->skipped_per_second;
	
		if (seconds) {
			stats_ptr->avg_pages_per_second = (stats_ptr->total_pages / seconds);
			stats_ptr->avg_bytes_per_second = (stats_ptr->total_bytes / seconds);
			stats_ptr->avg_errors_per_second = (stats_ptr->total_errors / seconds);
			stats_ptr->avg_dropped_per_second = (stats_ptr->total_dropped / seconds);
			stats_ptr->avg_aborts_per_second = (stats_ptr->total_aborts / seconds);
			stats_ptr->avg_skipped_per_second = (stats_ptr->total_skipped / seconds);
		}

		strncpy(stats_ptr->db_host, db_host, MAX_SQL_HOSTNAME);
		stats_ptr->db_host[MAX_SQL_HOSTNAME] = '\0';
		strncpy(stats_ptr->db_name, db_name, MAX_SQL_DATABASE_NAME);
		stats_ptr->db_name[MAX_SQL_DATABASE_NAME] = '\0';
		strncpy(stats_ptr->db_table, db_table, MAX_SQL_TABLE_NAME);
		stats_ptr->db_table[MAX_SQL_TABLE_NAME] = '\0';
		strncpy(stats_ptr->db_user, db_user, MAX_SQL_USER_NAME);
		stats_ptr->db_user[MAX_SQL_USER_NAME] = '\0';
		strncpy(stats_ptr->db_pass, "******", MAX_SQL_PASSWORD);
		stats_ptr->db_pass[MAX_SQL_PASSWORD] = '\0';
		strncpy(stats_ptr->db_path, db_path, MAX_PATH_LENGTH);
		stats_ptr->db_path[MAX_PATH_LENGTH] = '\0';
		stats_ptr->db_max_size = db_max_size;
		stats_ptr->skip_length = skip_length;
		stats_ptr->condensed_max_length = condensed_max_length;
		stats_ptr->show_skipped_requests = show_skipped_requests;
		stats_ptr->db_mode = db_mode;
#if 0
		stats_ptr->db_init_startup = db_init_startup;
#endif
		stats_ptr->db_free_space_threshold = db_free_space_threshold;
		
		mysql_free_space = mysql_free_size(db_path);
		stats_ptr->mysql_free_space = mysql_free_space;
	}
}


int leaf_truncate_log(void)
{
	if (truncate("/tmp/leaf.log", 0) == -1) {
           ci_debug_printf(4, "leaf: error truncating logfile %i\n", errno);
	   return 0;
	}	
	return 1;
}

int leaf_store_log(char *inbuf, size_t inlen)
{
        int fd_log;

        if ((fd_log = open("/tmp/leaf.log", O_CREAT | O_WRONLY | O_APPEND | O_SYNC, 0666)) == -1) {
           ci_debug_printf(4, "leaf: error opening logfile %i\n", errno);
           return 0;
        }

        if (lseek(fd_log, 0L, SEEK_END) == -1) {
           ci_debug_printf(4, "leaf: error writing logfile %i\n", errno);
           close(fd_log);
           return 0;
        }

        if (inlen) {
           if (write(fd_log, inbuf, inlen) != inlen) {
              ci_debug_printf(4, "leaf: error writing logfile %i\n", errno);
              close(fd_log);
              return 0;
           }
        }
        close(fd_log);
	return 1;
}

