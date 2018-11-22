#ifndef _DIAL_SNMP_H_
#define _DIAL_SNMP_H_

#include <net-snmp/net-snmp-config.h>  
#include <net-snmp/net-snmp-includes.h>  
#include <string.h>  
#include <stdio.h>
#include <string>
#include <iostream>

#include "Dial_list.h"
#include "Dial_server.h"

#define CMD_SIZE 128
#define CMD_RES_SIZE 4096


enum dev_type
{   
		ROUTER,
		SWITCH,
		SERVERS,
		HOST,
		XSHELL
};

enum sys_info_type
{
		LOAD,
		USERCPU,
		SYSCPU,
		IDLECPU,
		TOTALMEM,
		FREEMEM,
		USEDMEM,
		BUFFER,
		CACHE
};

enum route_info_type
{
		ROUTE_INDEX,
		ROUTE_TYPE,
		ROUTE_PROTO,
		ROUTE_NEXTHOP,
		ROUTE_MASK	
};

enum interface_traffic_type
{
		TRAFFIC_IN,
		TRAFFIC_OUT
};

enum interface_in_type
{
		INTERFACE_TYPE,
		INTERFACE_STATUS,
		INTERFACE_MTU,
		INTERFACE_PHYS,
		INTERFACE_DESCR,
		INTERFACE_SPEED
};

typedef struct outoctets_name
{
		int type;
		char name[32];

}arg_name_t;


typedef struct eth_traffic
{
		long long int inoctets;
		long long int outoctets;

}eth_traffic_t;

typedef struct eth_traffic_node
{
		int index;
		eth_traffic_t traffic;

}eth_traffic_node_t;

typedef struct eth_node 
{
		int index;
		char descr[32];    
		int type;    
		int status;    
		int mtu;
		long long int speed;
		char physaddress[64];

}eth_node_t;

typedef struct snmp_dev_node
{
		bool enable;
		bool start_flag;
		char name[32];
		char user[32];
		char passwd[32];
		char community[32];
		int port;
		int version;
		int interval;
		ip_info_t ip;

}snmp_dev_node_t;


typedef struct arp_map
{
		int arp_index;
		ip_info_t ip;
		char physaddress[64];

}arp_map_t;

typedef struct sys_info
{
		int load;
		int user_cpu;		
		int sys_cpu;		
		int idle_cpu;
		int total_mem;
		int free_mem;
		int buffer;
		int cache;
		int avail_mem;

}sys_info_t;

typedef struct process_info
{
		DIAL_LIST_NODE node;
		char name[32];
		bool exist_flag;
		int pid;
		int cpu_time;
		int used_mem;

}process_info_t;

typedef struct route_info
{
		int index;
		int type;
		int proto;
		ip_info_t dest;
		ip_info_t next;
		ip_info_t mask;

}route_info_t;


void* snmp_work_thread(void * arg);
void* ipsec_work_thread(void * arg);

#endif
