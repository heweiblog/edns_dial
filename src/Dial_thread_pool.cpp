#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <stdlib.h>
#include "Dial_server.h"
#include "Dial_queue.h"
#include "Dial_thread_pool.h"
#include "Dial_common.h"
#include "Dial_list.h"


inline void healthgroup_record_free(DIAL_LIST_HEAD* head)
{
		DIAL_LIST_NODE * cur = NULL;
		DIAL_LIST_NODE * tmp = NULL;
		record_info_t * record = NULL;

		list_for_each_safe(cur,tmp,&head->head)
		{
				record = (record_info_t*)cur;
				free(record);
		}
}


inline void nginxgroup_srv_free(DIAL_LIST_HEAD* head)
{
		DIAL_LIST_NODE * cur = NULL;
		DIAL_LIST_NODE * tmp = NULL;
		nginx_srv_t * srv = NULL;

		list_for_each_safe(cur,tmp,&head->head)
		{
				srv = (nginx_srv_t*)cur;
				free(srv);
		}
}


void task_node_free(dial_node_t * task_node)
{
		switch(task_node->type)
		{
				case HEALTHGROUP:
				{
						healthgroup_record_free(&task_node->dial_node.healthgroup->record_head);
						free(task_node->dial_node.healthgroup);
						break;
				}
				case DC:
				case SERVER:
				{
						free(task_node->dial_node.srv);
						break;
				}
				case NGINX:
				{
						nginxgroup_srv_free(&task_node->dial_node.nginxgroup->srv_head);
						free(task_node->dial_node.nginxgroup);
						break;
				}
				default:
				{
						break;
				}
		}

		free(task_node);
}


void * threadpool_worker_thread(void *arg)
{
		extern queue_info_t		queue_info;
		extern bool				client_connecting_flag;
		extern int				primary_flag;
		threadpool_t *tp = (threadpool_t *)arg;
		DIAL_LIST_NODE *node = NULL;
		dial_node_t *task_node = NULL;


		while(tp->threads_run_flag) 
		{
				pthread_mutex_lock(&tp->mutex);
				pthread_cond_wait(&tp->cond,&tp->mutex);
				pthread_mutex_unlock(&tp->mutex);

				if (tp->threads_run_flag==0) 
				{
						break;
				}

				pthread_mutex_lock(&tp->lock);
				tp->threads_used++;
				pthread_mutex_unlock(&tp->lock);

				while(NULL != (node = queue_pop(&queue_info))) 
				{
						task_node = (dial_node_t *)node;

						if(false == client_connecting_flag || 1 != primary_flag)
						{
								task_node_free(task_node);
								break;
						}

						switch(task_node->type)
						{
								case HEALTHGROUP:
								{
										do_a_dial_healthgroup(task_node->dial_node.healthgroup,task_node->policy);
										break;
								} 
								case SERVER:
								{
										do_a_dial_server(task_node->dial_node.srv);
										break;
								}
								case NGINX:
								{
										do_a_dial_nginxgroup(task_node->dial_node.nginxgroup,task_node->policy);
										break;
								}
								case DC:
								{
										do_a_dial_dc(task_node->dial_node.srv,task_node->policy);
										break;
								}
						}

						task_node_free(task_node);

				}

				pthread_mutex_lock(&tp->lock);
				tp->threads_used--;
				pthread_mutex_unlock(&tp->lock);

		}

		pthread_mutex_lock(&tp->lock);
		tp->act_threads_num--;
		pthread_mutex_unlock(&tp->lock);

}


int threadpool_init(threadpool_t *tp,int hope_threads_num)
{
		int i = 0;
		int ret = 0;

		tp->hope_threads_num = hope_threads_num;
		tp->threads_used = 0;
		tp->worker_thread_ids = (pthread_t *)malloc(hope_threads_num*sizeof(pthread_t));
		tp->new_worker_thread_ids = NULL;
		tp->threads_run_flag = 1;
		tp->act_threads_num = 0;

		if ((ret = pthread_mutex_init(&tp->mutex,NULL))!=0) 
		{
				return ret;
		}	
		if ((ret = pthread_mutex_init(&tp->lock,NULL))!=0) 
		{
				return ret;
		}	
		if ((ret = pthread_cond_init(&tp->cond,NULL))!=0) 
		{
				return ret;
		}	

		for(i=0;i<hope_threads_num;i++)
		{

				if ((ret = pthread_create(&tp->worker_thread_ids[i],NULL,threadpool_worker_thread,tp))!=0) 
				{
						return ret;
				}
				tp->act_threads_num++;
		}

		return 0;

}


int threadpool_destroy(threadpool_t *tp)
{
		int i = 0;
		tp->threads_run_flag = 0;

		pthread_cond_broadcast(&tp->cond);

		while(tp->act_threads_num>0)
		{
				usleep(1*1000);
				pthread_cond_broadcast(&tp->cond);

		}
		for(i=0;i<tp->hope_threads_num;i++)
		{
				pthread_join(tp->worker_thread_ids[i],NULL);
		}

		free(tp->worker_thread_ids);

		return 0;

}









