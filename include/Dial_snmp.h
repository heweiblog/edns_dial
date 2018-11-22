#ifndef _DIAL_SNMP_H_
#define _DIAL_SNMP_H_

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
		ROUTE_DEST,
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
		INTERFACE_INDEX,
		INTERFACE_TYPE,
		INTERFACE_STATUS,
		INTERFACE_MTU,
		INTERFACE_PHYS,
		INTERFACE_DESCR,
		INTERFACE_SPEED
};

enum process_arg_type
{
		PROCESS_CPU,
		PROCESS_MEM
};

typedef struct arg_name
{
		int type;
		char name[32];

}arg_name_t;


typedef struct eth_traffic
{
		int64_t inoctets;
		int64_t outoctets;

}eth_traffic_t;

typedef struct eth_traffic_node
{
		int index;
		eth_traffic_t traffic;

}eth_traffic_node_t;


void* snmp_work_thread(void * arg);

int handle_snmp_dialing(const char*ip,const char* user,const char* pass,
				const char* oid,const char*community,int version,const int port,int* delay);


#endif
