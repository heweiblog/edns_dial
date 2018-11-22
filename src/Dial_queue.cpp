#include "Dial_queue.h"
#include "Dial_thread_pool.h"



void queue_push(queue_info_t *info,DIAL_LIST_NODE *node)
{	
	pthread_mutex_lock(&info->lock);
	
	if(NULL == info->head) 
	{			
		info->head = node;
		info->tail = info->head;
	} 
	else 
	{
		info->head->next = node;
		info->head = node;
	}
	info->cnt++;
	
	pthread_mutex_unlock(&info->lock);
}


DIAL_LIST_NODE *queue_pop(queue_info_t *info)
{	
	DIAL_LIST_NODE *node = NULL;

	pthread_mutex_lock(&info->lock);
	
	if(NULL != info->tail) 
	{
		node = info->tail;
		info->tail = node->next;
		info->cnt--;
	}
	else
	{
		info->head = info->tail;
		info->cnt = 0;
	}

	pthread_mutex_unlock(&info->lock);

	return node;
}



void queue_clear(queue_info_t *info)
{
	DIAL_LIST_NODE *node = NULL;

	pthread_mutex_lock(&info->lock);
	
	while(NULL != info->tail) 
	{
		node = info->tail;
		info->tail = node->next;
		info->cnt--;
		task_node_free((dial_node_t *)node);		
	}
	
	info->head = NULL;

	pthread_mutex_unlock(&info->lock);

}



void queue_init(queue_info_t *info)
{
	info->cnt = 0;
	info->head = NULL;
	info->tail = NULL;
	pthread_mutex_init(&info->lock,NULL);
}








