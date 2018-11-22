#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <netdb.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/ip_icmp.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <vector>
#include <map>

#include "Dial_server.h"
#include "Dial_icmp.h"
#include "Dial_common.h"

uint32_t cal_mask(int val)
{
		int i = 0;
		uint32_t res = 1;
		for(i = 0 ; i < val ; i++)
		{
				res *= 2;		
		}
		res -= 1;
		return ~res;
}

int create_ipsec_raw_socket()
{
		int rtn = 0;
		int fd;
		struct timeval timeout;
		int fdbuflen;


		fd = socket(PF_INET, SOCK_RAW,IPPROTO_ICMP);
		if(fd < 0) 
		{
				debug_printf(LOG_LEVEL_ERROR,"create_client_raw_socket: socket failed,errno=%d\n",errno);
				return ERROR;
		}

		fdbuflen = 1024*1024*256;
		rtn = setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &fdbuflen, sizeof(int));
		if(rtn < 0)
		{
				debug_printf(LOG_LEVEL_ERROR,"setsockopt SO_SNDBUF failed,errno=%d\n",errno);
				close(fd);
				return ERROR;
		}

		timeout.tv_sec = 0;
		timeout.tv_usec = 1000*100;
		rtn = setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,(char *)&timeout,sizeof(struct timeval));
		if(rtn < 0)
		{
				debug_printf(LOG_LEVEL_ERROR,"create_client_raw_socket:setsockopt SO_RCVTIMEO failed,errno=%d\n",errno);
				close(fd);
				return ERROR;
		}


		timeout.tv_sec=0;
		timeout.tv_usec = 1000;
		rtn = setsockopt(fd,SOL_SOCKET,SO_SNDTIMEO,(char *)&timeout,sizeof(struct timeval));
		if(rtn < 0)
		{
				debug_printf(LOG_LEVEL_ERROR,"create_client_raw_socket:setsockopt SO_SNDTIMEO failed,errno=%d\n",errno);
				close(fd);
				return ERROR;
		}

		return fd;
}


void* ipsec_work_thread(void * arg)
{
		extern bool client_connecting_flag;
		extern bool thread_exit_flag;
		extern pthread_rwlock_t ipsec_map_lock;
		extern int 	primary_flag;	
		extern map<string,ipsec_node_t> ipsec_map;
		ipsec_node_t* ipsec = (ipsec_node_t*)arg;
		const char* ip = ipsec->ipsec.ipsec.ip.addr.c_str();
		uint32_t net_addr = 0,host_addr = 0,broadcast_addr = 0;
		uint32_t i = 0,host_mask = 0,net_begin_addr = 0,tmp_addr = 0;
		int rtn = 0,fd = 0,j = 0;
		char addr[32] = {'\0'};

		fd = create_ipsec_raw_socket();
		if(fd < 0)
		{
				debug_printf(LOG_LEVEL_ERROR,"create_client_raw_socket: socket failed,ipsec_work_exit ipsec=%s\n",ip);

				if(0 == ipsec->interval)
				{
						cfg_debug_printf(LOG_LEVEL_BASIC,"ipsec_thread will exit ipsec=%s\n",ip);
						pthread_rwlock_wrlock(&ipsec_map_lock);
						ipsec_map.erase(ipsec->ipsec.recordId);
						pthread_rwlock_unlock(&ipsec_map_lock);
				}		
				ipsec->work_flag = false;
				return 	NULL;
		}

		host_mask = cal_mask(32 - ipsec->ipsec.ipsec.mask);
		inet_pton(AF_INET,ip,&net_addr);
		host_addr = ntohl(net_addr);
		net_begin_addr = host_addr & host_mask;
		broadcast_addr = (~host_mask)|host_addr;

		vector<IpAddr> iplist;
		IpAddr tmp_ip;
		tmp_ip.version = 4;

		while(ipsec->work_flag)
		{
				if(false == client_connecting_flag)
				{
						sleep(1);
						continue;
				}

				for(i = net_begin_addr ; i <= broadcast_addr ; i++)
				{
						if(false == ipsec->work_flag)
						{
								cfg_debug_printf(LOG_LEVEL_BASIC,"%s:%d:thread will exit clear iplist_size=%d\n",__func__,__LINE__,iplist.size());
								iplist.clear();
								return NULL;
						}

						rtn = ipsec_ping(fd,i);

						if(1 == rtn)
						{
								memset(addr,0,32);
								tmp_addr = htonl(i);
								inet_ntop(AF_INET,&tmp_addr,addr,32);
								tmp_ip.addr.assign(addr);
								iplist.push_back(tmp_ip);
						}
				}
				
				update_ipsec_online_ip(ipsec->ipsec.recordId,iplist);
				iplist.clear();

				if(0 == ipsec->interval)
				{
						cfg_debug_printf(LOG_LEVEL_BASIC,"ipsec_thread will exit ipsec=%s\n",ip);
						pthread_rwlock_wrlock(&ipsec_map_lock);
						ipsec_map.erase(ipsec->ipsec.recordId);
						pthread_rwlock_unlock(&ipsec_map_lock);

						ipsec->work_flag = false;
						return NULL;
				}

				for(j = 0 ; j < ipsec->interval ; j++)
				{
						if(false == ipsec->work_flag)
						{
								cfg_debug_printf(LOG_LEVEL_BASIC,"ipsec_thread will exit ipsec=%s\n",ip);
								return NULL;
						}
						sleep(1);
				}

		}

		ipsec->work_flag = false;
		return NULL;
}
