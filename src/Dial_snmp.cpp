#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <net-snmp/net-snmp-config.h>  
#include <net-snmp/net-snmp-includes.h>  

#include "Dial_server.h"
#include "Dial_snmp.h"
#include "Dial_common.h"

#define CMD_SIZE 512
#define CMD_RES_SIZE 1024*1024

void get_cmd(const SnmpGroupInfo & snmp_node,char*snmp_cmd,int size,const char*oid)
{
		memset(snmp_cmd,0,size);

		if(3 == snmp_node.version)
		{
				sprintf(snmp_cmd,"snmpwalk -v 3 -u %s -a MD5 -A \"%s\" -l authNoPriv %s %s",snmp_node.user.c_str(),snmp_node.passwd.c_str(),snmp_node.ip.addr.c_str(),oid);
		}
		else if(2 == snmp_node.version)
		{
				sprintf(snmp_cmd,"snmpwalk -v 2c -c %s %s %s",snmp_node.community.c_str(),snmp_node.ip.addr.c_str(),oid);
		}
		else if(1 == snmp_node.version)
		{
				sprintf(snmp_cmd,"snmpwalk -v 1 -c %s %s %s",snmp_node.community.c_str(),snmp_node.ip.addr.c_str(),oid);
		}
}

void get_process_cmd(const SnmpGroupInfo & snmp_node,char*snmp_cmd,int size,const char*process_name)
{
		memset(snmp_cmd,0,size);

		if(3 == snmp_node.version)
		{
				sprintf(snmp_cmd,"snmpwalk -v 3 -u %s -a MD5 -A \"%s\" -l authNoPriv %s .1.3.6.1.2.1.25.4.2.1.2|grep \"%s\"",snmp_node.user.c_str(),snmp_node.passwd.c_str(),snmp_node.ip.addr.c_str(),process_name);
		}
		else if(2 == snmp_node.version)
		{
				sprintf(snmp_cmd,"snmpwalk -v 2c -c %s %s .1.3.6.1.2.1.25.4.2.1.2 | grep \"%s\"",snmp_node.community.c_str(),snmp_node.ip.addr.c_str(),process_name);
		}
		else if(1 == snmp_node.version)
		{
				sprintf(snmp_cmd,"snmpwalk -v 1 -c %s %s .1.3.6.1.2.1.25.4.2.1.2 | grep \"%s\"",snmp_node.community.c_str(),snmp_node.ip.addr.c_str(),process_name);
		}

}

void insert(char *str, char pch, int pos)
{
		int l = strlen(str);
		for(int i = l - 1; i >= pos; --i){
				*(str + i + 1) = *(str + i);
		}
		*(str + pos) = pch;
		*(str + l + 1) = 0;
}

void mac_check(char *s)
{
		int len = strlen(s);
		if(len >= 17 || len == 0)
		{
				return;
		}
		int i = 0,j = 0;

		for(i = 0 ; i < len+j; i++)
		{
				if(s[i] == ':' && (i == 1 || s[i-2] == ':'))
				{
					insert(s,'0',i-1);
					i++;
					j++;
				}
		}

		int rlen = strlen(s);
		if(s[rlen-2] == ':')
		{
				insert(s,'0',rlen-1);
		}		
}

int get_arp_map(snmp_node_t* snmp_node,vector<IpMac> & arp_map)
{
		char*p_buf = NULL;
		char*p_tmp = NULL;
		char* p_data = NULL;
		char* p_start = NULL;
		int i = 0,buf_len = 0;
		char index_buf[8];
		char snmp_cmd[CMD_SIZE];
		char tmp_buf[CMD_SIZE];
		char tmp_addr[CMD_SIZE];
		char tmp_mac[CMD_SIZE];
		char* cmd_res = (char*)malloc(CMD_RES_SIZE);

		get_cmd(snmp_node->snmp,snmp_cmd,CMD_SIZE,".1.3.6.1.2.1.4.22.1.2");

		FILE* fp = popen(snmp_cmd,"r");
		if(NULL == fp)
		{
				debug_printf(LOG_LEVEL_BASIC,"%s-%d-error cmd=%s\n",__func__,__LINE__,snmp_cmd);
				free(cmd_res);
				return -1;
		}

		memset(cmd_res,0,CMD_RES_SIZE);
		fread(cmd_res,CMD_RES_SIZE,1,fp);
		buf_len = strlen(cmd_res);
		if(buf_len <= 0 || buf_len > CMD_RES_SIZE - 1 || strstr(cmd_res,"No Such"))
		{
				debug_printf(LOG_LEVEL_ERROR,"%s-%d-result error cmd=%s,res_size=%d\n",__func__,__LINE__,snmp_cmd,buf_len);
				pclose(fp);
				free(cmd_res);
				return -1;	
		}

		p_buf = cmd_res;
		p_tmp = cmd_res;
		i = 0;

		while(*p_buf++)
		{
				if(*p_buf == '\n')
				{
						IpMac tmp_arp;
						*p_buf = '\0';
						memset(tmp_buf,0,CMD_SIZE);
						strcpy(tmp_buf,p_tmp);

						p_data = strchr(tmp_buf,'.');

						p_start = ++p_data;
						while('.' != *p_data++);
						if(p_data - p_start)
						{
								memset(index_buf,0,sizeof(index_buf));
								memcpy(index_buf,p_start,p_data-p_start);
								tmp_arp.index = atoi(index_buf);
						}

						p_start = p_data;
						if(p_data = strchr(tmp_buf,' '))
						{
								memset(tmp_addr,0,CMD_SIZE);
								memcpy(tmp_addr,p_start,p_data-p_start);
								tmp_arp.ip.addr.assign(tmp_addr);
						}

						p_data = strrchr(tmp_buf,' ');

						if('\0' == *(p_data+1))
						{
								i++;
								p_buf++;
								p_tmp = p_buf;
						}
						else
						{
								p_data += 1;
								memset(tmp_mac,0,CMD_SIZE);
								strcpy(tmp_mac,p_data);
								mac_check(tmp_mac);
								if(strcmp(tmp_mac,"00:00:00:00:00:00"))
								{
										tmp_arp.physaddress.assign(tmp_mac);
										arp_map.push_back(tmp_arp);
								}
								i++;
								p_buf++;
								p_tmp = p_buf;
						}	
				}
		}

		pclose(fp);
		free(cmd_res);

		return 0;
}

int get_interface_info(snmp_node_t* snmp_node,int size,vector<InterfaceInfo> & eth)
{
		FILE* fp = NULL;
		char*p_buf = NULL;
		char*p_tmp = NULL;
		char* p_data = NULL;
		int i = 0,j = 0,buf_len = 0;
		char tmp_buf[CMD_SIZE];
		char tmp_mac[CMD_SIZE];
		char snmp_cmd[CMD_SIZE];
		char* cmd_res = (char*)malloc(CMD_RES_SIZE);

		#if 0
		arg_name_t interface_arg[] = 
		{{INTERFACE_INDEX,".1.3.6.1.2.1.2.2.1.1"},{INTERFACE_TYPE,".1.3.6.1.2.1.2.2.1.3"},
		{INTERFACE_STATUS,".1.3.6.1.2.1.2.2.1.8"},{INTERFACE_MTU,".1.3.6.1.2.1.2.2.1.4"},
		{INTERFACE_PHYS,".1.3.6.1.2.1.2.2.1.6"},{INTERFACE_DESCR,".1.3.6.1.2.1.2.2.1.2"},
		{INTERFACE_SPEED,".1.3.6.1.2.1.2.2.1.5"}};
		#endif

		arg_name_t interface_arg[] = {{INTERFACE_INDEX,".1.3.6.1.2.1.2.2.1.1"},{INTERFACE_PHYS,".1.3.6.1.2.1.2.2.1.6"},{INTERFACE_DESCR,".1.3.6.1.2.1.2.2.1.2"},{INTERFACE_SPEED,".1.3.6.1.2.1.2.2.1.5"}};

		for(j = 0 ; j < (int)(sizeof(interface_arg)/sizeof(interface_arg[0])) ; j++)
		{
				get_cmd(snmp_node->snmp,snmp_cmd,CMD_SIZE,interface_arg[j].name);

				fp = popen(snmp_cmd,"r");
				if(NULL == fp)
				{
						debug_printf(LOG_LEVEL_ERROR,"%s-%d-error cmd=%s\n",__func__,__LINE__,snmp_cmd);
						free(cmd_res);
						return -1;
				}

				memset(cmd_res,0,CMD_RES_SIZE);
				fread(cmd_res,CMD_RES_SIZE,1,fp);
				buf_len = strlen(cmd_res);
				if(buf_len <= 0 || buf_len >= CMD_RES_SIZE - 1 || strstr(cmd_res,"No Such"))
				{
						debug_printf(LOG_LEVEL_ERROR,"%s-%d-result error cmd=%s,res_size=%d\n",__func__,__LINE__,snmp_cmd,buf_len);
						pclose(fp);
						free(cmd_res);
						return -1;	
				}

				p_buf = cmd_res;
				p_tmp = cmd_res;
				i = 0;

				while(*p_buf++)
				{
						if(*p_buf == '\n')
						{
								*p_buf = '\0';
								memset(tmp_buf,0,CMD_SIZE);
								strcpy(tmp_buf,p_tmp);
								p_data = strrchr(tmp_buf,' ');
								if('\0' == *(p_data+1))
								{
										i++;
										p_buf++;
										p_tmp = p_buf;
								}
								else
								{
										p_data += 1;
										switch(interface_arg[j].type)
										{
												case INTERFACE_INDEX:
												{
														eth[i].index = atoi(p_data);
														break;
												}
												case INTERFACE_PHYS:
												{
														memset(tmp_mac,0,CMD_SIZE);
														strcpy(tmp_mac,p_data);
														mac_check(tmp_mac);
														eth[i].physaddress.assign(tmp_mac);
														break;
												}
												case INTERFACE_DESCR:
												{
														eth[i].descr.assign(p_data);
														break;
												}
												case INTERFACE_TYPE:
												{
														p_data = strrchr(tmp_buf,')');
														*p_data = '\0';
														p_data = strrchr(tmp_buf,'(');
														p_data += 1;
														eth[i].type = atoi(p_data);
														break;
												}
												case INTERFACE_STATUS:
												{
														p_data = strrchr(tmp_buf,'(');
														p_data += 1;
														eth[i].status = *p_data - '0';
														break;
												}
												case INTERFACE_SPEED:
												{
														eth[i].speed = atol(p_data);
														break;
												}
												case INTERFACE_MTU:
												{
														eth[i].mtu = atoi(p_data);
														break;
												}
										}
										i++;
										p_buf++;
										p_tmp = p_buf;
								}	
						}
				}

				pclose(fp);

				if(i != size)
				{
						debug_printf(LOG_LEVEL_BASIC,"%s-%d-result error cmd=%s,interface size=%d\n",__func__,__LINE__,snmp_cmd,i);
				}
		}

		free(cmd_res);
		return 0;
}

int get_interface_traffic(snmp_node* snmp_node,vector<InterfaceTraffic> & eth,int size)
{
		FILE* fp = NULL;
		char*p_buf = NULL;
		char*p_tmp = NULL;
		char* p_data = NULL;
		int i = 0,j = 0,buf_len = 0;
		char tmp_buf[CMD_SIZE];
		char snmp_cmd[CMD_SIZE];
		char* cmd_res = (char*)malloc(CMD_RES_SIZE);
		arg_name_t traffic_arg[] = {{TRAFFIC_OUT,".1.3.6.1.2.1.2.2.1.16"},{TRAFFIC_IN,".1.3.6.1.2.1.2.2.1.10"}};


		for(j = 0 ; j < (int)(sizeof(traffic_arg)/sizeof(traffic_arg[0])) ; j++)
		{
				get_cmd(snmp_node->snmp,snmp_cmd,CMD_SIZE,traffic_arg[j].name);

				fp = popen(snmp_cmd,"r");
				if(NULL == fp)
				{
						debug_printf(LOG_LEVEL_ERROR,"%s-%d-error cmd=%s\n",__func__,__LINE__,snmp_cmd);
						free(cmd_res);
						return -1;
				}

				memset(cmd_res,0,CMD_RES_SIZE);
				fread(cmd_res,CMD_RES_SIZE,1,fp);
				buf_len = strlen(cmd_res);
				if(buf_len <= 0 || buf_len >= CMD_RES_SIZE - 1 || strstr(cmd_res,"No Such"))
				{
						debug_printf(LOG_LEVEL_ERROR,"%s-%d-result error cmd=%s,res_size=%d\n",__func__,__LINE__,snmp_cmd,buf_len);
						pclose(fp);
						free(cmd_res);
						return -1;	
				}

				p_buf = cmd_res;
				p_tmp = cmd_res;
				i = 0;

				while(*p_buf++)
				{
						if(*p_buf == '\n')
						{
								*p_buf = '\0';
								memset(tmp_buf,0,CMD_SIZE);
								strcpy(tmp_buf,p_tmp);
								p_data = strrchr(tmp_buf,' ');
								if('\0' == *(p_data+1))
								{
										i++;
										p_buf++;
										p_tmp = p_buf;
								}
								else
								{
										p_data += 1;
										switch(traffic_arg[j].type)
										{
												case TRAFFIC_OUT: 
												{
														eth[i].outoctets = atol(p_data);
														break;
												}
												case TRAFFIC_IN:
												{
														eth[i].inoctets = atol(p_data);
														break;
												}
										}
										i++;
										p_buf++;
										p_tmp = p_buf;
								}	
						}
				}

				pclose(fp);

				if(i != size)
				{
						debug_printf(LOG_LEVEL_BASIC,"%s-%d-result error cmd=%s,size=%d\n",__func__,__LINE__,snmp_cmd,i);
				}
		}

		free(cmd_res);
		return 0;
}


void del_str_space(char* buf)
{
		int i = 0;

		while(buf[i])
		{
				if(buf[i] == ' ')
				{
						buf[i] = ':';
				}
				i++;
		}

		if(':' == buf[i-1])
		{
				buf[i-1] = '\0';
		}
}


int get_interface_num(snmp_node_t* snmp_node,const char*oid)
{
		char* p_data = NULL;
		int buf_len = 0,eth_num = 0;
		char snmp_cmd[CMD_SIZE];

		get_cmd(snmp_node->snmp,snmp_cmd,CMD_SIZE,oid);

		FILE* fp = popen(snmp_cmd,"r");
		if(NULL == fp)
		{
				debug_printf(LOG_LEVEL_ERROR,"%s-%d-error cmd=%s\n",__func__,__LINE__,snmp_cmd);
				return -1;
		}

		char* cmd_res = (char*)malloc(CMD_RES_SIZE);
		memset(cmd_res,0,CMD_SIZE);
		fread(cmd_res,CMD_SIZE,1,fp);
		buf_len = strlen(cmd_res);
		if(buf_len <= 0 || buf_len >= CMD_SIZE - 1 || strstr(cmd_res,"No Such"))
		{
				debug_printf(LOG_LEVEL_ERROR,"%s-%d-result error cmd=%s,res_size=%d\n",__func__,__LINE__,snmp_cmd,buf_len);
				pclose(fp);
				free(cmd_res);
				return -1;	
		}

		p_data = strrchr(cmd_res,' ');
		if('\0' == *(p_data+1))
		{
				debug_printf(LOG_LEVEL_ERROR,"%s result error cmd=%s\n",__func__,snmp_cmd);
				pclose(fp);
				free(cmd_res);
				return -1;
		}
		else
		{
				p_data += 1;
				eth_num = atoi(p_data);
		}

		pclose(fp);
		free(cmd_res);

		return eth_num;
}


int get_sys_info(snmp_node_t* snmp_node,SysInfo & sys)
{
		FILE* fp = NULL;
		char* p_data = NULL;
		int j = 0,buf_len = 0;
		char snmp_cmd[CMD_SIZE];
		char* cmd_res = (char*)malloc(CMD_RES_SIZE);
		arg_name_t sys_arg[] = {{LOAD,".1.3.6.1.4.1.2021.10.1.5.3"},{USERCPU,".1.3.6.1.4.1.2021.11.9.0"},
		{SYSCPU,".1.3.6.1.4.1.2021.11.10.0"},{IDLECPU,".1.3.6.1.4.1.2021.11.11.0"},{TOTALMEM,".1.3.6.1.4.1.2021.4.5.0"},
		{FREEMEM,".1.3.6.1.4.1.2021.4.6.0"},{BUFFER,".1.3.6.1.4.1.2021.4.14.0"},{CACHE,".1.3.6.1.4.1.2021.4.15.0"}};


		for(j = 0 ; j < (int)(sizeof(sys_arg)/sizeof(sys_arg[0])) ; j++)
		{
				get_cmd(snmp_node->snmp,snmp_cmd,CMD_SIZE,sys_arg[j].name);

				fp = popen(snmp_cmd,"r");
				if(NULL == fp)
				{
						debug_printf(LOG_LEVEL_ERROR,"%s-%d-error cmd=%s\n",__func__,__LINE__,snmp_cmd);
						free(cmd_res);
						return -1;
				}

				memset(cmd_res,0,CMD_SIZE);
				fread(cmd_res,CMD_SIZE,1,fp);
				buf_len = strlen(cmd_res);
				if(buf_len <= 0 || buf_len >= CMD_SIZE - 1 || strstr(cmd_res,"No Such"))
				{
						debug_printf(LOG_LEVEL_ERROR,"%s-%d-result error cmd=%s,res_size=%d\n",__func__,__LINE__,snmp_cmd,buf_len);
						pclose(fp);
						free(cmd_res);
						return -1;	
				}

				p_data = strrchr(cmd_res,' ');
				if('\0' == *(p_data+1))
				{
						continue;
				}
				else
				{
						switch(sys_arg[j].type)
						{
								case LOAD:
								{
										sys.load = atoi(p_data+1);
										break;
								}
								case USERCPU:
								{
										sys.usercpu = atoi(p_data+1);  
										break;					
								}
								case SYSCPU:
								{
										sys.syscpu = atoi(p_data+1);
										break;					
								}
								case IDLECPU:
								{
										sys.idlecpu = atoi(p_data+1);
										break;					
								}
								case TOTALMEM:
								{
										*p_data = '\0';
										while(' ' != *p_data--);
										sys.totalmem = atoi(p_data+1);
										break;					
								}
								case FREEMEM:
								{
										*p_data = '\0';
										while(' ' != *p_data--);
										sys.freemem = atoi(p_data+1);
										break;					
								}
								case BUFFER:
								{
										*p_data = '\0';
										while(' ' != *p_data--);
										sys.buffer = atoi(p_data+1);
										break;					
								}
								case CACHE:
								{
										*p_data = '\0';
										while(' ' != *p_data--);
										sys.cache = atoi(p_data+1);
										break;					
								}
						}
				}
				pclose(fp);
		}

		free(cmd_res);
		return 0;
}


int get_process_info(snmp_node_t* snmp_node,const char*poid,int type)
{
		char* p_data = NULL;
		int buf_len = 0,res = 0;
		char snmp_cmd[CMD_SIZE];

		get_cmd(snmp_node->snmp,snmp_cmd,CMD_SIZE,poid);

		FILE* fp = popen(snmp_cmd,"r");
		if(NULL == fp)
		{
				debug_printf(LOG_LEVEL_ERROR,"%s-%d-error cmd=%s\n",__func__,__LINE__,snmp_cmd);
				return -1;
		}

		char* cmd_res = (char*)malloc(CMD_RES_SIZE);
		memset(cmd_res,0,CMD_SIZE);
		fread(cmd_res,CMD_RES_SIZE,1,fp);
		buf_len = strlen(cmd_res);
		if(buf_len <= 0 || buf_len >= CMD_RES_SIZE - 1 || strstr(cmd_res,"No Such"))
		{
				debug_printf(LOG_LEVEL_BASIC,"%s result error cmd=%s,res_size=%d\n",__func__,snmp_cmd,buf_len);
				pclose(fp);
				free(cmd_res);
				return -1;	
		}

		p_data = strrchr(cmd_res,' ');
		if('\0' == *(p_data+1))
		{
				debug_printf(LOG_LEVEL_ERROR,"%s-%d-error cmd=%s\n",__func__,__LINE__,snmp_cmd);
				pclose(fp);
				free(cmd_res);
				return -1;
		}
		else
		{
				switch(type)
				{
						case PROCESS_CPU:
						{
								res = atoi(p_data+1);
								break;
						}
						case PROCESS_MEM:
						{
								*p_data = '\0';
								while(' ' != *p_data--);
								res = atoi(p_data+1);
								break;
						}
				}		
		}

		pclose(fp);
		free(cmd_res);

		return res;
}

int get_process_pid(const SnmpGroupInfo & snmp_node,const char*process_name)
{
		char*p_buf = NULL;
		char*p_tmp = NULL;
		char* p_data = NULL;
		int buf_len = 0,pid = 0,tmp_pid = 0;
		char snmp_cmd[CMD_SIZE];
		char tmp_buf[CMD_SIZE];
		char pid_buf[CMD_SIZE];
		
		get_process_cmd(snmp_node,snmp_cmd,CMD_SIZE,process_name);

		FILE* fp = popen(snmp_cmd,"r");
		if(NULL == fp)
		{
				debug_printf(LOG_LEVEL_ERROR,"%s-%d-error cmd=%s\n",__func__,__LINE__,snmp_cmd);
				return -1;
		}

		char* cmd_res = (char*)malloc(CMD_RES_SIZE);
		memset(cmd_res,0,CMD_RES_SIZE);
		fread(cmd_res,CMD_RES_SIZE,1,fp);
		buf_len = strlen(cmd_res);
		if(buf_len <= 0 || buf_len >= CMD_RES_SIZE - 1 || strstr(cmd_res,"No Such"))
		{
				debug_printf(LOG_LEVEL_ERROR,"%s-%d-result error cmd=%s,res_size=%d\n",__func__,__LINE__,snmp_cmd,buf_len);
				pclose(fp);
				free(cmd_res);
				return -1;	
		}

		p_buf = cmd_res;
		p_tmp = cmd_res;

		while(*p_buf++)
		{
				if(*p_buf == '\n')
				{
						*p_buf = '\0';
						memset(tmp_buf,0,CMD_SIZE);
						strcpy(tmp_buf,p_tmp);

						if(p_data = strstr(tmp_buf,process_name))
						{
								memset(pid_buf,0,CMD_SIZE);
								strncpy(pid_buf,strchr(tmp_buf,'.')+1,(strchr(tmp_buf,' ') - strchr(tmp_buf,'.') - 1));
								tmp_pid = atoi(pid_buf);
								if(tmp_pid > pid)
								{
										pid = tmp_pid;
										tmp_pid = 0;
								}

						}
						p_buf++;
						p_tmp = p_buf;
				}
		}

		pclose(fp);
		free(cmd_res);

		return pid;

}

int get_route_num(snmp_node_t* snmp_node,vector<RouteInfo> & route)
{
		char*p_buf = NULL;
		char*p_tmp = NULL;
		char* p_data = NULL;
		int buf_len = 0;
		char tmp_buf[CMD_SIZE];
		char snmp_cmd[CMD_SIZE];

		get_cmd(snmp_node->snmp,snmp_cmd,CMD_SIZE,".1.3.6.1.2.1.4.21.1.2");

		FILE* fp = popen(snmp_cmd,"r");
		if(NULL == fp)
		{
				debug_printf(LOG_LEVEL_ERROR,"%s-%d-error cmd=%s\n",__func__,__LINE__,snmp_cmd);
				return -1;
		}

		char* cmd_res = (char*)malloc(CMD_RES_SIZE);
		memset(cmd_res,0,CMD_RES_SIZE);
		fread(cmd_res,CMD_RES_SIZE,1,fp);
		buf_len = strlen(cmd_res);
		if(buf_len <= 0 || buf_len >= CMD_RES_SIZE - 1 || strstr(cmd_res,"No Such"))
		{
				debug_printf(LOG_LEVEL_ERROR,"%s-%d-result error cmd=%s,res_size=%d\n",__func__,__LINE__,snmp_cmd,buf_len);
				pclose(fp);
				free(cmd_res);
				return -1;	
		}

		p_buf = cmd_res;
		p_tmp = cmd_res;

		while(*p_buf++)
		{
				if(*p_buf == '\n')
				{
						*p_buf = '\0';
						memset(tmp_buf,0,CMD_SIZE);
						strcpy(tmp_buf,p_tmp);
						p_data = strrchr(tmp_buf,' ');
						if('\0' == *(p_data+1))
						{
								p_buf++;
								p_tmp = p_buf;
						}
						else
						{
								RouteInfo tmp_route;
								p_data += 1;
								tmp_route.ifindex = atoi(p_data);
								p_buf++;
								p_tmp = p_buf;
								route.push_back(tmp_route);
						}	
				}
		}

		pclose(fp);
		free(cmd_res);

		return 0;
}

int get_route_info(snmp_node_t* snmp_node,vector<RouteInfo> & route,int size)
{
		FILE* fp = NULL;
		char*p_buf = NULL;
		char*p_tmp = NULL;
		char* p_data = NULL;
		int i = 0,j = 0,buf_len = 0;
		char tmp_buf[CMD_SIZE];
		char* cmd_res = (char*)malloc(CMD_RES_SIZE);
		char snmp_cmd[CMD_SIZE];
		arg_name_t route_arg[] = {{ROUTE_DEST,".1.3.6.1.2.1.4.21.1.1"},{ROUTE_TYPE,".1.3.6.1.2.1.4.21.1.8"},
		{ROUTE_PROTO,".1.3.6.1.2.1.4.21.1.9"},{ROUTE_NEXTHOP,".1.3.6.1.2.1.4.21.1.7"},{ROUTE_MASK,".1.3.6.1.2.1.4.21.1.11"}};


		for(j = 0 ; j < (int)(sizeof(route_arg)/sizeof(route_arg[0])) ; j++)
		{
				get_cmd(snmp_node->snmp,snmp_cmd,CMD_SIZE,route_arg[j].name);

				fp = popen(snmp_cmd,"r");
				if(NULL == fp)
				{
						debug_printf(LOG_LEVEL_ERROR,"%s-%d-error cmd=%s\n",__func__,__LINE__,snmp_cmd);
						free(cmd_res);
						return -1;
				}

				memset(cmd_res,0,CMD_RES_SIZE);
				fread(cmd_res,CMD_RES_SIZE,1,fp);
				buf_len = strlen(cmd_res);
				if(buf_len <= 0 || buf_len >= CMD_RES_SIZE - 1 || strstr(cmd_res,"No Such"))
				{
						debug_printf(LOG_LEVEL_ERROR,"%s-%d-result error cmd=%s,res_size=%d\n",__func__,__LINE__,snmp_cmd,buf_len);
						pclose(fp);
						free(cmd_res);
						return -1;	
				}

				p_buf = cmd_res;
				p_tmp = cmd_res;
				i = 0;

				while(*p_buf++)
				{
						if(*p_buf == '\n')
						{
								*p_buf = '\0';
								memset(tmp_buf,0,CMD_SIZE);
								strcpy(tmp_buf,p_tmp);
								p_data = strrchr(tmp_buf,' ');
								if('\0' == *(p_data+1))
								{
										i++;
										p_buf++;
										p_tmp = p_buf;
								}
								else
								{
										switch(route_arg[j].type)
										{
												case ROUTE_TYPE:
												{
														p_data = strrchr(tmp_buf,'(');
														p_data += 1;
														route[i].type = *p_data - '0';
														break;
												}
												case ROUTE_PROTO:
												{
														p_data = strrchr(tmp_buf,')');
														*p_data = '\0';
														p_data = strrchr(tmp_buf,'(');
														p_data += 1;
														route[i].proto = atoi(p_data);
														break;
												}
												case ROUTE_NEXTHOP:
												{
														p_data += 1;
														route[i].gateway.addr.assign(p_data);
														break;
												}
												case ROUTE_DEST:
												{
														p_data += 1;
														route[i].destination.addr.assign(p_data);
														break;
												}
												case ROUTE_MASK:
												{
														p_data += 1;
														route[i].genmask.addr.assign(p_data);
														break;
												}
										}
										i++;
										p_buf++;
										p_tmp = p_buf;
								}	
						}
				}

				pclose(fp);

				if(i != size)
				{
						debug_printf(LOG_LEVEL_BASIC,"%s-%d-result error cmd=%s,size=%d\n",__func__,__LINE__,snmp_cmd,i);
				}
		}

		free(cmd_res);
					
		return 0;
}


void update_snmp_node_process(snmp_node_t * snmp_node,vector<ProcessInfo> & process)
{
		int used_mem = 0,cpu_time = 0,i = 0,pid = 0;
		int size = process.size();
		char poid[CMD_SIZE];

		for(i = 0 ; i < size ; i++)
		{
				if(!process[i].pid)		
				{
						pid = get_process_pid(snmp_node->snmp,process[i].name.c_str());
						if(pid > 0)
						{
								process[i].existflag = true;
								process[i].pid = pid;
						}
						else
						{
								process[i].existflag = false;
								process[i].pid = -1;
								continue;
						}
				}
				if(process[i].existflag)
				{
						memset(poid,0,CMD_SIZE);
						sprintf(poid,".1.3.6.1.2.1.25.5.1.1.2.%d",process[i].pid);
						used_mem = get_process_info(snmp_node,(const char*)poid,PROCESS_MEM);
						if(used_mem > 0)
						{
								process[i].usedmem = used_mem;
						}

						memset(poid,0,CMD_SIZE);
						sprintf(poid,".1.3.6.1.2.1.25.5.1.1.1.%d",process[i].pid);
						cpu_time = get_process_info(snmp_node,(const char*)poid,PROCESS_CPU);
						if(cpu_time > 0)
						{
								process[i].cputime = cpu_time;
						}
				}

				debug_printf(LOG_LEVEL_DEBUG,"%s-process:name=%s,pid=%d,cputime=%d,usedmem=%d\n",
				snmp_node->snmp.ip.addr.c_str(),process[i].name.c_str(),process[i].pid,process[i].cputime,process[i].usedmem);

				update_process_info(snmp_node->snmp.name,process[i]);
		}

}


int get_mactable_outindex(snmp_node_t* snmp_node,vector<InterfaceInfo> & eth,vector<MacTable> & mac_table)
{
		char*p_buf = NULL;
		char*p_tmp = NULL;
		char* p_data = NULL;
		char* p_start = NULL;
		int i = 0,j = 0,buf_len = 0,phy_num = 0,out_num = 0,eth_size = eth.size(),mac_table_size = mac_table.size();
		char index_buf[8];
		char snmp_cmd[CMD_SIZE];
		char tmp_buf[CMD_SIZE];
		char oid[CMD_SIZE];
		char cmd_res[CMD_RES_SIZE];

		get_cmd(snmp_node->snmp,snmp_cmd,CMD_SIZE,".1.3.6.1.2.1.17.4.3.1.2");

		FILE* fp = popen(snmp_cmd,"r");
		if(NULL == fp)
		{
				debug_printf(LOG_LEVEL_ERROR,"%s-%d-error cmd=%s\n",__func__,__LINE__,snmp_cmd);
				return -1;
		}

		memset(cmd_res,0,CMD_RES_SIZE);
		fread(cmd_res,CMD_RES_SIZE,1,fp);
		buf_len = strlen(cmd_res);
		if(buf_len <= 0 || buf_len >= CMD_RES_SIZE - 1 || strstr(cmd_res,"No Such"))
		{
				debug_printf(LOG_LEVEL_ERROR,"%s-%d-result error cmd=%s,res_size=%d\n",__func__,__LINE__,snmp_cmd,buf_len);
				pclose(fp);
				return -1;	
		}

		p_buf = cmd_res;
		p_tmp = cmd_res;
		i = 0;

		while(*p_buf++)
		{
				if(*p_buf == '\n')
				{
						MacTable tmp_arp;
						*p_buf = '\0';
						memset(tmp_buf,0,CMD_SIZE);
						strcpy(tmp_buf,p_tmp);
						p_data = strrchr(tmp_buf,' ');
						if('\0' == *(p_data+1))
						{
								i++;
								p_buf++;
								p_tmp = p_buf;
						}
						else
						{
								p_data += 1;

								out_num = atoi(p_data);
								//mac_table[i].out_index = out_num;

								memset(oid,0,CMD_SIZE);
								sprintf(oid,".1.3.6.1.2.1.17.1.4.1.2.%d",out_num);
								phy_num = get_interface_num(snmp_node,oid);

								mac_table[i].index = phy_num;

								for(j = 0 ; j < eth_size ; j++)
								{
										if(eth[j].index == phy_num)
										{
												mac_table[i].portname = eth[j].descr;
										}
								}

								i++;
								p_buf++;
								p_tmp = p_buf;
						}

				}
		}

		pclose(fp);

		if(i != mac_table_size)
		{
				debug_printf(LOG_LEVEL_DEBUG,"%s-%d-real_size=%d,mac_table_szie=%d\n",__func__,__LINE__,snmp_cmd,i,mac_table_size);
				//return -1;
		}

		return 0;
}

void mac_change_ch(char*str)
{
		while(*str++)
		{
				if(*str == ' ')
				{
						*str = ':';
				}
				//*str = *str + 32;
		}
		if(*(str-2) == ':')
		{
				*(str-2) = '\0';
		}
}

int get_mactable(snmp_node_t* snmp_node,vector<InterfaceInfo> & eth,vector<MacTable> & mac_table)
{
		char*p_buf = NULL;
		char*p_tmp = NULL;
		char* p_data = NULL;
		char* p_start = NULL;
		int i = 0,buf_len = 0,phy_port = 0,eth_size = eth.size();
		char snmp_cmd[CMD_SIZE];
		char tmp_buf[CMD_SIZE];
		char tmp_mac[CMD_SIZE];
		char cmd_res[CMD_RES_SIZE];

		get_cmd(snmp_node->snmp,snmp_cmd,CMD_SIZE,".1.3.6.1.2.1.17.4.3.1.1");

		FILE* fp = popen(snmp_cmd,"r");
		if(NULL == fp)
		{
				debug_printf(LOG_LEVEL_ERROR,"%s-%d-error cmd=%s\n",__func__,__LINE__,snmp_cmd);
				return -1;
		}

		memset(cmd_res,0,CMD_RES_SIZE);
		fread(cmd_res,CMD_RES_SIZE,1,fp);
		buf_len = strlen(cmd_res);
		if(buf_len <= 0 || buf_len >= CMD_RES_SIZE - 1 || strstr(cmd_res,"No Such"))
		{
				debug_printf(LOG_LEVEL_ERROR,"%s-%d-result error cmd=%s,res_size=%d\n",__func__,__LINE__,snmp_cmd,buf_len);
				pclose(fp);
				return -1;	
		}

		p_buf = cmd_res;
		p_tmp = cmd_res;
		i = 0;

		while(*p_buf++)
		{
				if(*p_buf == '\n')
				{
						MacTable tmp_arp;
						*p_buf = '\0';
						memset(tmp_buf,0,CMD_SIZE);
						strcpy(tmp_buf,p_tmp);
						p_data = strrchr(tmp_buf,':');
						if('\0' == *(p_data+2))
						{
								i++;
								p_buf++;
								p_tmp = p_buf;
						}
						else
						{
								p_data += 2;
								memset(tmp_mac,0,CMD_SIZE);
								strcpy(tmp_mac,p_data);
								mac_change_ch(tmp_mac);
								tmp_arp.macaddress.assign(tmp_mac);
								mac_table.push_back(tmp_arp);
								i++;
								p_buf++;
								p_tmp = p_buf;
						}

				}
		}

		pclose(fp);

		int rtn = get_mactable_outindex(snmp_node,eth,mac_table);

		return rtn;
}


void* snmp_work_thread(void * arg)
{
		extern bool client_connecting_flag;
		extern int 	primary_flag;	
		snmp_node_t * snmp_node = (snmp_node_t*)arg;
		int i = 0,eth_num = 0,res = 0,route_size = 0;
		int64_t outoctets = 0,inoctets = 0;

		vector<InterfaceTraffic> eth_traffic(eth_num);
		InterfaceTraffic tmp_eth_traffic;
	
		InterfaceInfo tmp_eth;
		vector<InterfaceInfo> eth;	
		vector<RouteInfo> route;
		vector<IpMac> arp_map;	
		vector<MacTable> mac_table;	
		SysInfo sys;

		while(snmp_node->work_flag)
		{
				if(false == client_connecting_flag)
				{
						sleep(1);
						continue;
				}

				eth_num = get_interface_num(snmp_node,".1.3.6.1.2.1.2.1.0");
				if(eth_num < 0)
				{
						debug_printf(LOG_LEVEL_ERROR,"get_interface_num error snmp_ip=%s\n",snmp_node->snmp.ip.addr.c_str());
						snmp_node->work_flag = false;
						return NULL;
				}
				else
				{
						debug_printf(LOG_LEVEL_DEBUG,"%s-interface:num=%d\n",snmp_node->snmp.ip.addr.c_str(),eth_num);
				}
				
				if((int)eth.size() != eth_num)
				{
						eth.resize(eth_num,tmp_eth);	
						eth_traffic.resize(eth_num,tmp_eth_traffic);
				}
				else
				{
						eth.assign(eth_num,tmp_eth);	
						eth_traffic.assign(eth_num,tmp_eth_traffic);
				}
				
				res = get_interface_info(snmp_node,eth_num,eth);
				if(res < 0)
				{
						debug_printf(LOG_LEVEL_ERROR,"get_interface_info error snmp_ip=%s\n",snmp_node->snmp.ip.addr.c_str());
				}
				else
				{
						update_interface_info(snmp_node->snmp.name,eth);
				}

				for(i = 0 ; i < eth_num ; i++)
				{
						//debug_printf(LOG_LEVEL_DEBUG,"%s-interface:index=%d,descr=%s,physaddress=%s,type=%d,mtu=%d,status=%d,speed=%ld\n",snmp_node->snmp.ip.addr.c_str(),eth[i].index,eth[i].descr.c_str(),eth[i].physaddress.c_str(),eth[i].type,eth[i].mtu,eth[i].status,eth[i].speed);
						debug_printf(LOG_LEVEL_DEBUG,"%s-Interface:index=%d,descr=%s,physaddress=%s,speed=%ld\n",snmp_node->snmp.ip.addr.c_str(),eth[i].index,eth[i].descr.c_str(),eth[i].physaddress.c_str(),eth[i].speed);
				}

				route.clear();
				res = get_route_num(snmp_node,route);     
				if(res < 0)
				{
						debug_printf(LOG_LEVEL_ERROR,"get_route_num error snmp_ip=%s\n",snmp_node->snmp.ip.addr.c_str());
				}
				else
				{

						route_size = route.size();
						res = get_route_info(snmp_node,route,route_size);
						if(res < 0)
						{
								debug_printf(LOG_LEVEL_ERROR,"get_route_info error snmp_ip=%s\n",snmp_node->snmp.ip.addr.c_str());
						}
						else
						{
								update_route_info(snmp_node->snmp.name,route);
						}

						for(i = 0 ; i < route_size ; i++)
						{
								debug_printf(LOG_LEVEL_DEBUG,"%s-route:destination=%s,gateway=%s,genmask=%s,type=%d,proto=%d,interface_index=%d\n",
												snmp_node->snmp.ip.addr.c_str(),route[i].destination.addr.c_str(),route[i].gateway.addr.c_str(),
												route[i].genmask.addr.c_str(),route[i].type,route[i].proto,route[i].ifindex);
						}
				}

				mac_table.clear();
				res = get_mactable(snmp_node,eth,mac_table);
				if(res < 0)
				{
						debug_printf(LOG_LEVEL_DEBUG,"get_mac_table error snmp_ip=%s\n",snmp_node->snmp.ip.addr.c_str());
				}
				else
				{
						update_mac_table(snmp_node->snmp.name,mac_table);
						for(i = 0 ; i < (int)mac_table.size() ; i++)
						{
								debug_printf(LOG_LEVEL_DEBUG,"%s-MacTable:mac=%s,index=%d,port=%s\n",snmp_node->snmp.ip.addr.c_str(),mac_table[i].macaddress.c_str(),mac_table[i].index,mac_table[i].portname.c_str());
						}
				}

				arp_map.clear();
				res = get_arp_map(snmp_node,arp_map);
				if(res < 0)
				{
						debug_printf(LOG_LEVEL_ERROR,"get_interface_ip_mac error snmp_ip=%s\n",snmp_node->snmp.ip.addr.c_str());
				}
				else
				{
						update_interface_ipmac(snmp_node->snmp.name,arp_map);
						for(i = 0 ; i < (int)arp_map.size() ; i++)
						{
								debug_printf(LOG_LEVEL_DEBUG,"%s-ipmac:index=%d,ip=%s,mac=%s\n",snmp_node->snmp.ip.addr.c_str(),
												arp_map[i].index,arp_map[i].ip.addr.c_str(),arp_map[i].physaddress.c_str());
						}
				}

				#if 0
				res = get_sys_info(snmp_node,sys);
				if(res < 0)
				{
						debug_printf(LOG_LEVEL_ERROR,"get_sys_info error error snmp_ip=%s\n",snmp_node->snmp.ip.addr.c_str());
				}
				else
				{
						sys.availmem = sys.freemem + sys.buffer + sys.cache;

						debug_printf(LOG_LEVEL_DEBUG,"%s-sysinfo:load=%d,usercpu=%d,syscpu=%d,idlecpu=%d,totalmem=%d,freemem=%d,buffer=%d,cache=%d,availmem=%d\n",snmp_node->snmp.ip.addr.c_str(),sys.load,sys.usercpu,sys.syscpu,sys.idlecpu,sys.totalmem,sys.freemem,sys.buffer,sys.cache,sys.availmem);

						update_sys_info(snmp_node->snmp.name,sys);		
				}
				#endif
				
				#if 1
				if(!snmp_node->process.empty())
				{
						update_snmp_node_process(snmp_node,snmp_node->process);
				}
				#endif

				res = get_interface_traffic(snmp_node,eth_traffic,eth_num);
				if(res < 0)
				{
						debug_printf(LOG_LEVEL_ERROR,"get_interface_traffic error snmp_ip=%s\n",snmp_node->snmp.ip.addr.c_str());
				}
				else
				{
						for(i = 0 ; i < eth_num ; i++)
						{
								eth_traffic[i].index = eth[i].index;
								debug_printf(LOG_LEVEL_DEBUG,"%s-interface:index=%d,outoctets=%ld,inoctets=%ld\n",snmp_node->snmp.ip.addr.c_str(),eth_traffic[i].index,eth_traffic[i].outoctets,eth_traffic[i].inoctets);
						}
						update_interface_traffic(snmp_node->snmp.name,eth_traffic);
				}
				
				if(0 == snmp_node->snmp.interval)
				{
						break;
				}
				sleep(snmp_node->snmp.interval);	
		}

		snmp_node->work_flag = false;
		return NULL;

}

 
int handle_snmp_dialing(const char*ip,const char* user,const char* pass,
				const char* oid,const char*community,int version,const int port,int* delay)
{
		int status = 0,res = -1;
		char host[64] = {'\0'};
		netsnmp_session session,*ss = NULL;
		netsnmp_pdu *pdu = NULL;  
		netsnmp_pdu *response = NULL;
		ulong anOID[MAX_OID_LEN] = {0}; 
		size_t anOID_len =  0;
		netsnmp_variable_list *vars = NULL;  

		init_snmp("snmp");
		snmp_sess_init( &session ); 
		sprintf(host,"%s:%d",ip,port);
		session.peername = host;
		session.timeout = 80*1000;
		
		if(2 == version)
		{
				session.version = SNMP_VERSION_2c;
		}
		else if(3 == version)
		{
				//session.version = SNMP_VERSION_3;
				session.version = SNMP_VERSION_2c;
		}
		else
		{
				//session.version = SNMP_VERSION_1;
				session.version = SNMP_VERSION_2c;
		}

		if(SNMP_VERSION_3 == session.version)
		{
				session.securityName = (char*)user;
				session.securityNameLen = strlen(session.securityName);
				session.securityLevel = SNMP_SEC_LEVEL_AUTHNOPRIV;
				//session.securityLevel = SNMP_SEC_LEVEL_AUTHPRIV;
				session.securityAuthProto = usmHMACMD5AuthProtocol;
				session.securityAuthProtoLen = sizeof(usmHMACMD5AuthProtocol)/sizeof(oid);
				session.securityAuthKeyLen = USM_AUTH_KU_LEN;
				if (generate_Ku(session.securityAuthProto,
										session.securityAuthProtoLen,
										(u_char *)pass, strlen(pass),
										session.securityAuthKey,
										&session.securityAuthKeyLen) != SNMPERR_SUCCESS) {
						debug_printf(LOG_LEVEL_BASIC,"snmp v3 init error snmp_ip=%s\n",session.peername);
						return -1;
				}
		}
		else
		{
				session.community = (u_char*)community;  
				session.community_len = strlen(community);  
		}

		ss = snmp_open(&session);                
		if (!ss) 
		{
				debug_printf(LOG_LEVEL_BASIC,"snmp open init error snmp_ip=%s\n",session.peername);
				return -1;
		}


		pdu = snmp_pdu_create(SNMP_MSG_GET);  
		anOID_len = MAX_OID_LEN;  

		if (!snmp_parse_oid(oid, anOID, &anOID_len)) 
		{  
				debug_printf(LOG_LEVEL_ERROR,"%s-%d-snmp_parse_oid error,oid=%s,ip=%s!!!\n",__func__,__LINE__,oid,ip);
				return -1;
		}

		snmp_add_null_var(pdu, anOID, anOID_len); 

		struct timeval t_start;
		struct timeval t_end;
		gettimeofday(&t_start,NULL);

		status = snmp_synch_response(ss, pdu, &response);  

		if (status == STAT_SUCCESS && response->errstat == SNMP_ERR_NOERROR) 
		{
				gettimeofday(&t_end,NULL);
				*delay = ((t_end.tv_sec * 1000*1000 + t_end.tv_usec) - (t_start.tv_sec * 1000*1000 + t_start.tv_usec));
				debug_printf(LOG_LEVEL_DEBUG,"%s-%d-handle snmp policy dial success!!!,oid=%s,ip=%s!!!\n",__func__,__LINE__,oid,ip);
				res = 0;	
		}
		else
		{
				debug_printf(LOG_LEVEL_DEBUG,"%s-%d-handle snmp policy dial failed!!!,oid=%s,ip=%s!!!\n",__func__,__LINE__,oid,ip);
		}

		if(response) 
		{
				snmp_free_pdu(response);  
		}	

		snmp_close(ss); 
		return res;	
}

