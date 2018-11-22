#ifndef DIAL_SERVER_H
#define DIAL_SERVER_H

#include <time.h>
#include "Dial.h"
#include "dialrpc_types.h"
#include "Dial_list.h"
#include "Dial_ip.h"
#include "Dial_snmp.h"

using namespace ::rpc::dial::yamutech::com;
using namespace std;

typedef struct snmp_node
{
		bool work_flag;
		pthread_t tid;
		SnmpGroupInfo snmp;
		vector<ProcessInfo> process; 
	
}snmp_node_t;


typedef struct ipsec_node
{
		bool work_flag;
		pthread_t tid;
		int interval;
		SysIpSec ipsec;

}ipsec_node_t;


enum dial_type 
{
		DIAL_TCPPORT = 0,
		DIAL_IMCP = 1,
		DIAL_HTTPGET = 2,
		DIAL_DATABASE = 3,
		DIAL_EXTHTTPGET = 4,
		DIAL_EXTTCPPORT = 5,
		DIAL_EXTHTTPPOST = 6,
		DIAL_HTTPCOMMON = 7,
  		DIAL_UDPPORT = 8,
  		DIAL_FTP = 9,
  		DIAL_SMTP = 10,
  		DIAL_SNMP = 11,
  		DIAL_ORACLE = 12,
		DIAL_NETBIOS = 13,
};


enum dial_node_type 
{
		HEALTHGROUP = 0,
		SERVER = 1,
		NGINX = 2,
		DC = 3,
};


enum srv_type 
{
		XPROXY = 0,
		REDIRECT = 1,
		XFORWARD = 2,
		DATACENTER = 3,
};


typedef struct match_code_info 
{
		DIAL_LIST_NODE node;
		unsigned int code;

} match_code_t;


typedef struct record_node_info 
{
		DIAL_LIST_NODE node;
		char rid[50];
		ip_info_t ip;

} record_info_t;


typedef struct nginx_srv_node_info 
{
		DIAL_LIST_NODE node;
		char url[256];
		int priority;

} nginx_srv_t;


typedef struct dial_option_info 
{
		char dest_url[256];
		char test_method[4096];
		char expect_match[1024];
		char content_type[128];
		DIAL_LIST_HEAD code_head;
		int tag;

}dial_option_t;


typedef struct Healthpolicy_node_info 
{
		DIAL_LIST_NODE node;
		char policyname[50];
		short method;
		uint16_t port;
		int freq;
		int times;
		int passed;
		dial_option_t dial_option;

} healthpolicy_info_t;


typedef struct pPolicy_node_struct
{
		DIAL_LIST_NODE node;
		struct timeval t_insert;
		healthpolicy_info_t *pPolicy;

} pPolicy_node_t;


typedef struct Healthgroup_node_info 
{
		DIAL_LIST_NODE node;
		char name[50];
		DIAL_LIST_HEAD pPolicy_head;
		DIAL_LIST_HEAD record_head;

} healthgroup_info_t;


typedef struct nginxgroup_node_info
{
		DIAL_LIST_NODE node;
		char name[50];
		DIAL_LIST_HEAD pPolicy_head;
		DIAL_LIST_HEAD srv_head;

} nginxgroup_info_t;


typedef struct dial_server_node_info 
{
		DIAL_LIST_NODE node;
		DialServerType::type srv_tpye;
		char srv_id[50];
		ip_info_t ip;
		struct timeval t_insert;
		DIAL_LIST_HEAD pPolicy_head;

} dial_srv_node_t;


typedef struct dial_node_info 
{

		DIAL_LIST_NODE node;
		int type;
		healthpolicy_info_t* policy;
		union
		{
				dial_srv_node_t *srv;
				healthgroup_info_t *healthgroup;
				nginxgroup_info_t *nginxgroup;

		} dial_node;

} dial_node_t;


typedef struct  dial_server_config 
{
		int health;
		int delay_weight;
		int lost_weight;
		int count;
		int timeout;
		int interval;
		char dname[200];	

} dial_srv_cfg_t;


typedef struct  dial_config 
{
		dial_srv_cfg_t srv_cfg;
		int log_level;
		int agent_port;
		int dial_port;
		char agent_ip[26];
		char log_path[100];
		char certificate_file[512];	

} dial_cfg_t;

#define CMP_TIME(x,y)  ((x.tv_sec * 1000*1000 + x.tv_usec) - (y.tv_sec * 1000*1000 + y.tv_usec))

class DialHandler : virtual public DialIf 
{
		public:
				DialHandler() 
				{
						// Your initialization goes here
				}

				RetCode::type systemCommand(const SysCommand::type cmdType);
				RetCode::type addHealthGroup(const std::string& groupName, const std::string& policyName);
				RetCode::type delHealthGroup(const std::string& groupName, const std::string& policyName);
				RetCode::type addHealthRecord(const std::string& groupName, const std::vector<DialRecord> & records);
				RetCode::type delHealthRecord(const std::string& groupName, const std::vector<DialRecord> & records);
				RetCode::type addHealthPolicy(const HealthPolicyInfo& policy);
				RetCode::type modHealthPolicy(const HealthPolicyInfo& policy);
				RetCode::type delHealthPolicy(const HealthPolicyInfo& policy);
				RetCode::type addDialServer(const ObjectId& rid, const IpAddr& ip, const DialServerType::type typ);
				RetCode::type delDialServer(const ObjectId& rid);
				RetCode::type addNginxGroup(const std::string& groupName, const std::string& policyName);
				RetCode::type delNginxGroup(const std::string& groupName, const std::string& policyName);
				RetCode::type addNginxServer(const std::string& groupName, const std::vector<DialNginxServer> & servers);
				RetCode::type delNginxServer(const std::string& groupName, const std::vector<DialNginxServer> & servers);
				void heartBeat(HeartBeatState& _return);
				RetCode::type setServerState(const bool enable);
  				RetCode::type addSnmpGroupInfo(const SnmpGroupInfo& snmp);
  				RetCode::type delSnmpGroupInfo(const std::string& snmp);
  				RetCode::type addSnmpProcessInfo(const std::string& snmp, const std::string& processname);
  				RetCode::type delSnmpProcessInfo(const std::string& snmp, const std::string& processname);
  				RetCode::type addIpSec(const SysIpSec& ipsec,const int32_t interval);
  				RetCode::type delIpSec(const std::string& ipsecid);
  				RetCode::type addDcInfo(const DcInfo& dc);
  				RetCode::type delDcInfo(const std::string& id);
};


void do_a_dial_healthgroup(healthgroup_info_t *hg,healthpolicy_info_t *policy);

int do_a_dial_server(dial_srv_node_t *srv);

void do_a_dial_nginxgroup(nginxgroup_info_t *ng,healthpolicy_info_t *policy);

void do_a_dial_dc(dial_srv_node_t *srv,healthpolicy_info_t *policy);

void *client_reconnect_thread(void *arg);

int get_parameters_from_url(char *src,char *resource,char *ip,int *port,bool *https_flag);

void log_debug_open(int sig);

void log_debug_close(int sig);

int sys_log_timer_init();

int signal_init();

RetCode::type update_ipsec_online_ip(const std::string& ipsecid, const std::vector<IpAddr> & iplist);

RetCode::type update_interface_info(const std::string& snmp, const std::vector<InterfaceInfo> & interfaces);

RetCode::type update_interface_traffic(const std::string& snmp, const std::vector<InterfaceTraffic> & traffic);

RetCode::type update_interface_ipmac(const std::string& snmp, const std::vector<IpMac> & ipmac);

RetCode::type update_mac_table(const std::string& snmp, const std::vector<MacTable> & mactable);

RetCode::type update_route_info(const std::string& snmp, const std::vector<RouteInfo> & routeinfo);

RetCode::type update_sys_info(const std::string& snmp, const SysInfo& sysinfo);

RetCode::type update_process_info(const std::string& snmp, const ProcessInfo& processinfo);

#endif
