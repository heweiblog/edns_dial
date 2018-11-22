#ifndef DIAL_THREAD_POOL_
#define DIAL_THREAD_POOL_



#include <pthread.h>
#include "Dial_server.h"

typedef struct threadpool {

	int hope_threads_num;	
	int act_threads_num;	
	//int threads_used;	
	volatile int threads_used;	
	int threads_run_flag;		
	pthread_t *worker_thread_ids;
	pthread_t *new_worker_thread_ids;
	pthread_mutex_t mutex,lock;
	pthread_cond_t cond;
}threadpool_t;




void *threadpool_worker_thread(void *tp);

int threadpool_destroy(threadpool_t *tp);

int threadpool_init(threadpool_t *tp,int hope_threads_num);

inline void healthgroup_record_free(DIAL_LIST_HEAD* head);

inline void nginxgroup_srv_free(DIAL_LIST_HEAD* head);

void task_node_free(dial_node_t * task_node);

#endif

