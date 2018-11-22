#include "Dial_snmp.h"
#include "Dial_common.h"

int get_arp_map(const SnmpGroupInfo & snmp_node,vector<IpMac> & arp_map)
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
		char tmp_phy[CMD_SIZE];
		char cmd_res[CMD_RES_SIZE];
		memset(snmp_cmd,0,CMD_SIZE);

		if(SNMP_VERSION_3 == snmp_node.version)
		{
				sprintf(snmp_cmd,"snmpwalk -v 3 -u %s -a MD5 -A \"%s\" -l authNoPriv %s .1.3.6.1.2.1.4.22.1.2",snmp_node.user.c_str(),snmp_node.passwd.c_str(),snmp_node.ip.addr.c_str());
		}
		else if(SNMP_VERSION_2c == snmp_node.version)
		{
				sprintf(snmp_cmd,"snmpwalk -v 2c -c %s %s .1.3.6.1.2.1.4.22.1.2",snmp_node.community.c_str(),snmp_node.ip.addr.c_str());
		}
		else if(SNMP_VERSION_1 == snmp_node.version)
		{
				sprintf(snmp_cmd,"snmpwalk -v 1 -c %s %s .1.3.6.1.2.1.4.22.1.2",snmp_node.community.c_str(),snmp_node.ip.addr.c_str());
		}

		FILE* fp = popen(snmp_cmd,"r");
		if(NULL == fp)
		{
				return -1;
		}

		memset(cmd_res,0,CMD_RES_SIZE);
		fread(cmd_res,CMD_RES_SIZE,1,fp);
		buf_len = strlen(cmd_res);
		if(buf_len <= 0 || buf_len >= CMD_RES_SIZE - 1)
		{
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
								memset(tmp_phy,0,CMD_SIZE);
								memcpy(tmp_phy,p_start,p_data-p_start);
								tmp_arp.physaddress.assign(tmp_phy);
								i++;
								p_buf++;
								p_tmp = p_buf;
								arp_map.push_back(tmp_arp);
						}	
				}
		}

		pclose(fp);

		return 0;
}

int get_interface_index(const SnmpGroupInfo & snmp_node,int size,int *eth_index)
{
		char*p_buf = NULL;
		char*p_tmp = NULL;
		char* p_data = NULL;
		int i = 0,buf_len = 0;
		char snmp_cmd[CMD_SIZE];
		char tmp_buf[CMD_SIZE];
		char cmd_res[CMD_RES_SIZE];
		memset(snmp_cmd,0,CMD_SIZE);

		if(SNMP_VERSION_3 == snmp_node.version)
		{
				sprintf(snmp_cmd,"snmpwalk -v 3 -u %s -a MD5 -A \"%s\" -l authNoPriv %s .1.3.6.1.2.1.2.2.1.1",snmp_node.user.c_str(),snmp_node.passwd.c_str(),snmp_node.ip.addr.c_str());
		}
		else if(SNMP_VERSION_2c == snmp_node.version)
		{
				sprintf(snmp_cmd,"snmpwalk -v 2c -c %s %s .1.3.6.1.2.1.2.2.1.1",snmp_node.community.c_str(),snmp_node.ip.addr.c_str());
		}
		else if(SNMP_VERSION_1 == snmp_node.version)
		{
				sprintf(snmp_cmd,"snmpwalk -v 1 -c %s %s .1.3.6.1.2.1.2.2.1.1",snmp_node.community.c_str(),snmp_node.ip.addr.c_str());
		}

		FILE* fp = popen(snmp_cmd,"r");
		if(NULL == fp)
		{
				return -1;
		}

		memset(cmd_res,0,CMD_RES_SIZE);
		fread(cmd_res,CMD_RES_SIZE,1,fp);
		buf_len = strlen(cmd_res);
		if(buf_len <= 0 || buf_len >= CMD_RES_SIZE - 1)
		{
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
								eth_index[i] = atoi(p_data);
		debug_printf(LOG_LEVEL_BASIC,"%s-%d:eth_index[%d]=%d\n",__func__,__LINE__,pthread_self(),i,eth_index[i]);
								i++;
								p_buf++;
								p_tmp = p_buf;
						}	
				}
		}

		pclose(fp);

		if(i != size)
		{
				return -1;
		}

		return 0;
}

int get_interface_traffic(netsnmp_session*ss,vector<InterfaceTraffic> & eth,int size,int* eth_index,arg_name_t & arg)
{
		netsnmp_pdu *pdu = NULL;  
		netsnmp_pdu *response = NULL; 
		oid anOID[MAX_OID_LEN] = {0};	 
		netsnmp_variable_list *vars = NULL;  
		int status = 0,count = 0,i = 0;
		size_t anOID_len =  0;

		arg_name_t name[size];
		memset(name,0,sizeof(name));

		pdu = snmp_pdu_create(SNMP_MSG_GET);  
		anOID_len = MAX_OID_LEN; 

		for(i = 0 ; i < size ; i++)
		{
				sprintf(name[i].name,"%s.%d",arg.name,eth_index[i]);
				memset(anOID,0,MAX_OID_LEN);
				if (!snmp_parse_oid(name[i].name, anOID, &anOID_len)) 
				{  
						return -1;;  
				}

				snmp_add_null_var(pdu, anOID, anOID_len); 
		}

		status = snmp_synch_response(ss, pdu, &response);  

		if (status == STAT_SUCCESS && response->errstat == SNMP_ERR_NOERROR) 
		{
				for(vars = response->variables; vars; vars = vars->next_variable)
				{
						if(vars->type == ASN_COUNTER)
						{
								switch(arg.type)
								{
										case TRAFFIC_OUT: 
												{
														eth[count].outoctets = (unsigned long long int)(*vars->val.integer);
														count++;
														break;
												}
										case TRAFFIC_IN:
												{
														eth[count].inoctets = (unsigned long long int)(*vars->val.integer);
														count++;
														break;
												}
										default:
												{
														return -1;
												}
								}
						}
				}
		}
		else
		{ 	 
				if (status == STAT_SUCCESS)  
				{
						return -3;
				}	
				else if (status == STAT_TIMEOUT)
				{
						return -2;
				}			
				else
				{
						return -1;
				}	
		}

		if(response) 
		{
				snmp_free_pdu(response);  
		}	

		if(count != size)
		{
				return -1;
		}

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


int get_eth_num(netsnmp_session*ss)
{
		netsnmp_pdu *pdu = NULL;  
		netsnmp_pdu *response = NULL; 
		oid anOID[MAX_OID_LEN] = {0};	 
		size_t anOID_len =  0;
		netsnmp_variable_list *vars = NULL;  
		int status = 0,count = 0,i = 0,eth_num = 0;

		pdu = snmp_pdu_create(SNMP_MSG_GET);  
		anOID_len = MAX_OID_LEN;  

		memset(anOID,0,MAX_OID_LEN);
		//const char* poid = "ifNumber.0";     
		const char* poid = ".1.3.6.1.2.1.2.1.0";     
		if (!snmp_parse_oid(poid, anOID, &anOID_len)) 
		{  
				debug_printf(LOG_LEVEL_ERROR,"%s-%d-tid=%u,snmp_parse_oid error!!!\n",__func__,__LINE__,pthread_self());
				return -1;
		}

		snmp_add_null_var(pdu, anOID, anOID_len); 

		status = snmp_synch_response(ss, pdu, &response);  

		if (status == STAT_SUCCESS && response->errstat == SNMP_ERR_NOERROR) 
		{
				for(vars = response->variables; vars; vars = vars->next_variable)
				{
						if(vars->type == ASN_INTEGER)
						{
								eth_num = *(vars->val.integer);
								break;
						}
				}
		}
		else
		{ 	 
				if (status == STAT_SUCCESS)  
				{
		debug_printf(LOG_LEVEL_BASIC,"%s-%d-tid=%u\n",__func__,__LINE__,pthread_self());
						return -3;
				}	
				else if (status == STAT_TIMEOUT)
				{
		debug_printf(LOG_LEVEL_BASIC,"%s-%d-tid=%u\n",__func__,__LINE__,pthread_self());
						return -2;
				}			
				else
				{
		debug_printf(LOG_LEVEL_BASIC,"%s-%d-tid=%u\n",__func__,__LINE__,pthread_self());
						return -1;
				}	
		}

		if(response) 
		{
				snmp_free_pdu(response);  
		}	

		debug_printf(LOG_LEVEL_BASIC,"%s-%d-tid=%u,eth_num=%d\n",__func__,__LINE__,pthread_self(),eth_num);
		return eth_num;	
}


int get_sys_info(netsnmp_session*ss,SysInfo & sys,int size,arg_name_t * arg)
{
		netsnmp_pdu *pdu = NULL;  
		netsnmp_pdu *response = NULL; 
		oid anOID[MAX_OID_LEN] = {0};	 
		size_t anOID_len =  0;
		netsnmp_variable_list *vars = NULL;  
		int status = 0;  
		int count = 0;  
		int i = 0;

		pdu = snmp_pdu_create(SNMP_MSG_GET);  
		anOID_len = MAX_OID_LEN; 

		for(i = 0 ; i < size ; i++)
		{
				memset(anOID,0,MAX_OID_LEN);
				if (!snmp_parse_oid(arg[i].name, anOID, &anOID_len)) 
				{  
						return -1;;  
				}

				snmp_add_null_var(pdu, anOID, anOID_len); 
		}

		status = snmp_synch_response(ss, pdu, &response);  

		if (status == STAT_SUCCESS && response->errstat == SNMP_ERR_NOERROR) 
		{
				for(vars = response->variables; vars; vars = vars->next_variable)
				{
						if(vars->type == ASN_INTEGER)
						{
								switch(arg[count].type)
								{
										case LOAD:
										{
												sys.load = *(vars->val.integer);  
												count++;
												break;					
										}
										case USERCPU:
										{
												sys.usercpu = *(vars->val.integer);  
												count++;
												break;					
										}
										case SYSCPU:
										{
												sys.syscpu = *(vars->val.integer);  
												count++;
												break;					
										}
										case IDLECPU:
										{
												sys.idlecpu = *(vars->val.integer);  
												count++;
												break;					
										}
										case TOTALMEM:
										{
												sys.totalmem = *(vars->val.integer);  
												count++;
												break;					
										}
										case FREEMEM:
										{
												sys.freemem = *(vars->val.integer);  
												count++;
												break;					
										}
										case BUFFER:
										{
												sys.buffer = *(vars->val.integer);  
												count++;
												break;					
										}
										case CACHE:
										{
												sys.cache = *(vars->val.integer);  
												count++;
												break;					
										}
										default:
										{
												return -1;
										}
								}
						}
				}
		}
		else
		{ 	 
				if (status == STAT_SUCCESS)  
				{
						return -3;
				}	
				else if (status == STAT_TIMEOUT)
				{
						return -2;
				}			
				else
				{
						return -1;
				}	
		}

		if(response) 
		{
				snmp_free_pdu(response);  
		}	

		if(size != count)
		{
				return -1;
		}

		return 0;
}


int get_interface_info(netsnmp_session*ss,vector<InterfaceInfo> & eth,int size,int* eth_index,arg_name_t & arg)
{
		netsnmp_pdu *pdu = NULL;  
		netsnmp_pdu *response = NULL; 
		oid anOID[MAX_OID_LEN] = {0};	 
		size_t anOID_len =  0;
		netsnmp_variable_list *vars = NULL;  
		int status = 0;  
		int count = 0;  
		int i = 0;

		arg_name_t name[size];
		memset(name,0,sizeof(name));

		pdu = snmp_pdu_create(SNMP_MSG_GET);  
		anOID_len = MAX_OID_LEN; 

		for(i = 0 ; i < size ; i++)
		{
				eth[i].index = eth_index[i];
				sprintf(name[i].name,"%s.%d",arg.name,eth_index[i]);
				memset(anOID,0,MAX_OID_LEN);
				if (!snmp_parse_oid(name[i].name, anOID, &anOID_len)) 
				{  
						return -1;;  
				}

				snmp_add_null_var(pdu, anOID, anOID_len); 
		}

		status = snmp_synch_response(ss, pdu, &response);  

		if (status == STAT_SUCCESS && response->errstat == SNMP_ERR_NOERROR) 
		{
				for(vars = response->variables; vars; vars = vars->next_variable)
				{
						if(vars->type == ASN_INTEGER)
						{
								switch(arg.type)
								{
										case INTERFACE_TYPE:
										{
												eth[count].type = *(vars->val.integer);
												count++;
												break;
										}	
										case INTERFACE_STATUS:
										{
												eth[count].status = *(vars->val.integer);
												count++;
												break;
										}	
										case INTERFACE_MTU:
										{
												eth[count].mtu = *(vars->val.integer);
												count++;
												break;
										}
										default:
										{
												return -1;
										}
								}	
						}
						else if(vars->type == ASN_GAUGE)
						{
								eth[count].speed = *(vars->val.integer);
								count++;
						}
						else if (vars->type == ASN_OCTET_STR) 
						{
								int hex = 0;
								int x;
								u_char * cp;
								int allow_realloc = 1;
								u_char *buf = NULL;
								size_t buf_len = 256, out_len = 0;

								for (cp = vars->val.string, x = 0; x < (int) vars->val_len; x++, cp++) 
								{
										if (!isprint(*cp) && !isspace(*cp)) 
										{
												hex = 1;
										}
								}
								if(!hex) 
								{
										char *sp = (char *)calloc(1,1 + vars->val_len);
										memcpy(sp, vars->val.string, vars->val_len); 
										eth[count].descr.assign(sp);
										free(sp);
										count++;
								}
								else
								{
										buf = (u_char *) calloc(buf_len, 1);
										snmp_cstrcat(&buf, &buf_len, &out_len, allow_realloc, "");
										sprint_realloc_hexstring(&buf, &buf_len, &out_len, allow_realloc,vars->val.string, vars->val_len);
										del_str_space((char*)buf);
										eth[count].physaddress.assign((const char*)buf);
										free(buf);
										count++;
								}
						}
				}
		}
		else
		{ 	 
				if (status == STAT_SUCCESS)  
				{
						return -3;
				}	
				else if (status == STAT_TIMEOUT)
				{
						return -2;
				}			
				else
				{
						return -1;
				}	
		}

		if(response) 
		{
				snmp_free_pdu(response);  
		}	

		if(size != count)
		{
				return -1;
		}

		return 0;
}

int get_process_info(netsnmp_session*ss,const char*poid,int pid)
{
		netsnmp_pdu *pdu = NULL;  
		netsnmp_pdu *response = NULL; 
		oid anOID[MAX_OID_LEN] = {0};	 
		size_t anOID_len =  0;
		netsnmp_variable_list *vars = NULL;  
		int status = 0,count = 0,i = 0,process_arg = 0;

		pdu = snmp_pdu_create(SNMP_MSG_GET);  
		anOID_len = MAX_OID_LEN;  

		memset(anOID,0,MAX_OID_LEN);
		if (!snmp_parse_oid(poid, anOID, &anOID_len)) 
		{  
				return -1;
		}

		snmp_add_null_var(pdu, anOID, anOID_len); 

		status = snmp_synch_response(ss, pdu, &response);  

		if (status == STAT_SUCCESS && response->errstat == SNMP_ERR_NOERROR) 
		{
				for(vars = response->variables; vars; vars = vars->next_variable)
				{
						if(vars->type == ASN_INTEGER)
						{
								process_arg = *(vars->val.integer);
								break;
						}
				}
		}
		else
		{ 	 
				if (status == STAT_SUCCESS)  
				{
						return -3;
				}	
				else if (status == STAT_TIMEOUT)
				{
						return -2;
				}			
				else
				{
						return -1;
				}	
		}

		if(response) 
		{
				snmp_free_pdu(response);  
		}	

		return process_arg;	
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
		char process_buf[CMD_SIZE];
		char cmd_res[CMD_RES_SIZE];
		memset(snmp_cmd,0,CMD_SIZE);
		memset(process_buf,0,CMD_SIZE);

		sprintf(process_buf,"\"%s\"",process_name);

		if(SNMP_VERSION_3 == snmp_node.version)
		{
				sprintf(snmp_cmd,"snmpwalk -v 3 -u %s -a MD5 -A \"%s\" -l authNoPriv %s .1.3.6.1.2.1.25.4.2.1.2|grep %s",snmp_node.user.c_str(),snmp_node.passwd.c_str(),snmp_node.ip.addr.c_str(),process_name);
		}
		else if(SNMP_VERSION_2c == snmp_node.version)
		{
				sprintf(snmp_cmd,"snmpwalk -v 2c -c %s %s .1.3.6.1.2.1.25.4.2.1.2 | grep %s",snmp_node.community.c_str(),snmp_node.ip.addr.c_str(),process_name);
		}
		else if(SNMP_VERSION_1 == snmp_node.version)
		{
				sprintf(snmp_cmd,"snmpwalk -v 1 -c %s %s .1.3.6.1.2.1.25.4.2.1.2 | grep %s",snmp_node.community.c_str(),snmp_node.ip.addr.c_str(),process_name);
		}

		FILE* fp = popen(snmp_cmd,"r");
		if(NULL == fp)
		{
				return -1;
		}

		memset(cmd_res,0,CMD_RES_SIZE);
		fread(cmd_res,CMD_RES_SIZE,1,fp);
		buf_len = strlen(cmd_res);
		if(buf_len <= 0 || buf_len >= CMD_RES_SIZE - 1)
		{
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

						if(p_data = strstr(tmp_buf,process_buf))
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

		return pid;

}

int get_route_dest(const SnmpGroupInfo & snmp_node,vector<RouteInfo> & route)
{
		char*p_buf = NULL;
		char*p_tmp = NULL;
		char* p_data = NULL;
		int buf_len = 0;
		char snmp_cmd[CMD_SIZE];
		char tmp_buf[CMD_SIZE];
		char cmd_res[CMD_RES_SIZE];
		char tmp_addr[CMD_RES_SIZE];

		memset(snmp_cmd,0,CMD_SIZE);

		if(SNMP_VERSION_3 == snmp_node.version)
		{
				sprintf(snmp_cmd,"snmpwalk -v 3 -u %s -a MD5 -A \"%s\" -l authNoPriv %s .1.3.6.1.2.1.4.21.1.1",snmp_node.user.c_str(),snmp_node.passwd.c_str(),snmp_node.ip.addr.c_str());
		}
		else if(SNMP_VERSION_2c == snmp_node.version)
		{
				sprintf(snmp_cmd,"snmpwalk -v 2c -c %s %s .1.3.6.1.2.1.4.21.1.1",snmp_node.community.c_str(),snmp_node.ip.addr.c_str());
		}
		else if(SNMP_VERSION_1 == snmp_node.version)
		{
				sprintf(snmp_cmd,"snmpwalk -v 1 -c %s %s .1.3.6.1.2.1.4.21.1.1",snmp_node.community.c_str(),snmp_node.ip.addr.c_str());
		}

		FILE* fp = popen(snmp_cmd,"r");
		if(NULL == fp)
		{
				return -1;
		}

		memset(cmd_res,0,CMD_RES_SIZE);
		fread(cmd_res,CMD_RES_SIZE,1,fp);
		buf_len = strlen(cmd_res);
		if(buf_len <= 0 || buf_len >= CMD_RES_SIZE - 1)
		{
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
								memset(tmp_addr,0,CMD_RES_SIZE);
								strcpy(tmp_addr,p_data);
								tmp_route.destination.addr.assign(tmp_addr);
								p_buf++;
								p_tmp = p_buf;
								route.push_back(tmp_route);
						}	
				}
		}

		pclose(fp);

		return 0;
}

int get_route_info(netsnmp_session*ss,vector<RouteInfo> & route,int size,arg_name_t & arg)
{
		netsnmp_pdu *pdu = NULL;  
		netsnmp_pdu *response = NULL; 
		oid anOID[MAX_OID_LEN] = {0};	 
		size_t anOID_len =  0;
		netsnmp_variable_list *vars = NULL;  
		int status = 0;  
		int count = 0;  
		int i = 0;
		char route_arg[64] = {'\0'};
		char tmp_addr[CMD_RES_SIZE];

		pdu = snmp_pdu_create(SNMP_MSG_GET);  
		anOID_len = MAX_OID_LEN; 

		for(i = 0 ; i < size ; i++)
		{
				sprintf(route_arg,"%s.%s",arg.name,route[i].destination.addr.c_str());
				memset(anOID,0,MAX_OID_LEN);
				if (!snmp_parse_oid(route_arg, anOID, &anOID_len)) 
				{  
						return -1;;  
				}

				snmp_add_null_var(pdu, anOID, anOID_len); 
		}

		status = snmp_synch_response(ss, pdu, &response);  

		if (status == STAT_SUCCESS && response->errstat == SNMP_ERR_NOERROR) 
		{
				for(vars = response->variables; vars; vars = vars->next_variable)
				{
						if(vars->type == ASN_INTEGER)
						{
								switch(arg.type)
								{
										case ROUTE_INDEX:
										{
												route[count].ifindex = *(vars->val.integer);  
												count++;
												break;					
										}
										case ROUTE_TYPE:
										{
												route[count].type = *(vars->val.integer);  
												count++;
												break;					
										}
										case ROUTE_PROTO:
										{
												route[count].proto = *(vars->val.integer);  
												count++;
												break;					
										}
								}
						}
						else if(vars->type == ASN_IPADDRESS)
						{
								u_char *ip = vars->val.string;

								switch(arg.type)
								{
										case ROUTE_NEXTHOP:
										{
												memset(tmp_addr,0,CMD_RES_SIZE);
												sprintf(tmp_addr,"%d.%d.%d.%d",ip[0],ip[1],ip[2],ip[3]);
												route[count].destination.addr.assign(tmp_addr);
												count++;
												break;
										}
										case ROUTE_MASK:
										{
												memset(tmp_addr,0,CMD_RES_SIZE);
												sprintf(tmp_addr,"%d.%d.%d.%d",ip[0],ip[1],ip[2],ip[3]);
												route[count].genmask.addr.assign(tmp_addr);
												count++;
												break;
										}
								}
						}
				}
		}
		else
		{ 	 
				if (status == STAT_SUCCESS)  
				{
						return -3;
				}	
				else if (status == STAT_TIMEOUT)
				{
						return -2;
				}			
				else
				{
						return -1;
				}	
		}

		if(response) 
		{
				snmp_free_pdu(response);  
		}	

		if(size != count)
		{
				return -1;
		}

		return 0;
}


void update_snmp_node_process(netsnmp_session * ss,snmp_node_t * snmp_node,vector<ProcessInfo> & process)
{
		int used_mem = 0,cpu_time = 0,i = 0,pid = 0;
		char poid[CMD_SIZE] = {'\0'};
		int size = process.size();

		pthread_rwlock_rdlock(&snmp_node->process_lock);

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
								continue;
						}
				}
				if(process[i].existflag)
				{
						memset(poid,0,CMD_SIZE);
						sprintf(poid,".1.3.6.1.2.1.25.5.1.1.2.%d",process[i].pid);
						//sprintf(poid,"hrSWRunPerfMem.%d",process->pid);
						used_mem = get_process_info(ss,poid,process[i].pid);
						if(used_mem > 0)
						{
								process[i].usedmem = used_mem;
						}

						memset(poid,0,CMD_SIZE);
						sprintf(poid,".1.3.6.1.2.1.25.5.1.1.1.%d",process[i].pid);
						//sprintf(poid,"hrSWRunPerfCPU.%d",pid);
						cpu_time = get_process_info(ss,poid,process[i].pid);
						if(cpu_time > 0)
						{
								process[i].cputime = cpu_time;
						}
				}
				// 此处更新进程信息
				update_process_info(snmp_node->snmp.name,process[i]);
		}

		pthread_rwlock_unlock(&snmp_node->process_lock);

}


void* snmp_work_thread(void * arg)
{
		extern bool client_connecting_flag;
		extern bool thread_exit_flag;
		extern int 	primary_flag;	
		int i = 0,eth_num = 3,res = 0;
		long long int max_int = 0xffffffff;
		long long int outoctets = 0;
		long long int inoctets = 0;
		netsnmp_session session,*ss = NULL;
		snmp_node_t * snmp_node = (snmp_node_t*)arg;

		init_snmp("snmp");
		snmp_sess_init( &session ); 
		session.peername = (char*)snmp_node->snmp.ip.addr.c_str();   

		session.version = snmp_node->snmp.version;

		debug_printf(LOG_LEVEL_BASIC,"%s-%d-tid=%u\n",__func__,__LINE__,pthread_self());
		if(SNMP_VERSION_3 == session.version)
		{
				session.securityName = (char*)snmp_node->snmp.user.c_str();
				session.securityNameLen = strlen(session.securityName);
				session.securityLevel = SNMP_SEC_LEVEL_AUTHNOPRIV;
				//session.securityLevel = SNMP_SEC_LEVEL_AUTHPRIV;
				session.securityAuthProto = usmHMACMD5AuthProtocol;
				session.securityAuthProtoLen = sizeof(usmHMACMD5AuthProtocol)/sizeof(oid);
				session.securityAuthKeyLen = USM_AUTH_KU_LEN;
				if (generate_Ku(session.securityAuthProto,
										session.securityAuthProtoLen,
										(u_char *)snmp_node->snmp.passwd.c_str(), strlen(snmp_node->snmp.passwd.c_str()),
										session.securityAuthKey,
										&session.securityAuthKeyLen) != SNMPERR_SUCCESS) {
						debug_printf(LOG_LEVEL_BASIC,"snmp v3 init error snmp_ip=%s\n",session.peername);
						return NULL;
				}
		}
		else
		{
				session.community = (u_char*)snmp_node->snmp.community.c_str();  
				session.community_len = strlen((const char*)session.community);  
		}

		debug_printf(LOG_LEVEL_BASIC,"%s-%d-tid=%u\n",__func__,__LINE__,pthread_self());
		ss = snmp_open(&session);                
		if (!ss) 
		{
				debug_printf(LOG_LEVEL_BASIC,"snmp_openinit error snmp_ip=%s\n",session.peername);
				return NULL;
		}

		debug_printf(LOG_LEVEL_BASIC,"%s-%d-tid=%u\n",__func__,__LINE__,pthread_self());
		eth_num = get_eth_num(ss);
		if(eth_num < 0)
		{
				debug_printf(LOG_LEVEL_BASIC,"get_eth_num error snmp_ip=%s\n",session.peername);
				snmp_close(ss); 
				return NULL;
		}

		debug_printf(LOG_LEVEL_BASIC,"%s-%d-tid=%u\n",__func__,__LINE__,pthread_self());
		vector<InterfaceInfo> eth(eth_num);
		int eth_index[eth_num];
		
		/*
		eth_traffic_t traffic_start_out[eth_num];
		eth_traffic_t traffic_end_out[eth_num];
		eth_traffic_t traffic_start_in[eth_num];
		eth_traffic_t traffic_end_in[eth_num];
		eth_traffic_node_t eth_traffic[eth_num];
		*/

		vector<InterfaceTraffic> eth_traffic(eth_num);
		InterfaceTraffic tmp_eth_traffic;
		memset(&tmp_eth_traffic,0,sizeof(InterfaceTraffic));

		memset(eth_index,0,sizeof(eth_index));
		res = get_interface_index(snmp_node->snmp,eth_num,eth_index);
		if(res < 0)
		{
				debug_printf(LOG_LEVEL_BASIC,"get_interface_index error snmp_ip=%s\n",session.peername);
				snmp_close(ss); 
				return NULL;
		}

		arg_name_t interface_arg[] = {{INTERFACE_TYPE,".1.3.6.1.2.1.2.2.1.3"},{INTERFACE_STATUS,".1.3.6.1.2.1.2.2.1.8"},{INTERFACE_MTU,".1.3.6.1.2.1.2.2.1.4"},{INTERFACE_PHYS,".1.3.6.1.2.1.2.2.1.6"},{INTERFACE_DESCR,".1.3.6.1.2.1.2.2.1.2"},{INTERFACE_SPEED,".1.3.6.1.2.1.2.2.1.5"}};
		//arg_name_t interface_arg[] = {{INTERFACE_TYPE,"ifType"},{INTERFACE_STATUS,"ifOperStatus"},{INTERFACE_MTU,"ifMtu"},{INTERFACE_PHYS,"ifPhysAddress"},{INTERFACE_DESCR,"ifDescr"},{INTERFACE_SPEED,"ifSpeed"}};

		for(i = 0 ; i < (int)(sizeof(interface_arg)/sizeof(interface_arg[0])) ; i++)
		{
				res = get_interface_info(ss,eth,eth_num,eth_index,interface_arg[i]);
				if(res < 0)
				{
						debug_printf(LOG_LEVEL_BASIC,"get_interface_info error snmp_ip=%s\n",session.peername);
						snmp_close(ss); 
						return NULL;
				}
		}
		
		//上报端口基本信息
		update_interface_info(snmp_node->snmp.name,eth);

		vector<RouteInfo>route;
		res = get_route_dest(snmp_node->snmp,route);     
		if(res < 0)
		{
				debug_printf(LOG_LEVEL_BASIC,"get_route_dest error snmp_ip=%s\n",session.peername);
				snmp_close(ss); 
				return NULL;
		}

		int route_size = route.size();

		arg_name_t route_arg[] = {{ROUTE_INDEX,".1.3.6.1.2.1.4.21.1.2"},{ROUTE_TYPE,".1.3.6.1.2.1.4.21.1.8"},{ROUTE_PROTO,".1.3.6.1.2.1.4.21.1.9"},{ROUTE_NEXTHOP,".1.3.6.1.2.1.4.21.1.7"},{ROUTE_MASK,".1.3.6.1.2.1.4.21.1.11"}};
		//arg_name_t route_arg[] = {{ROUTE_INDEX,"ipRouteIfIndex"},{ROUTE_TYPE,"ipRouteType"},{ROUTE_PROTO,"ipRouteProto"},{ROUTE_NEXTHOP,"ipRouteNextHop"},{ROUTE_MASK,"ipRouteMask"}};

		for(i = 0 ; i < route_size ; i++) 
		{
				res = get_route_info(ss,route,route_size,route_arg[i]);
				if(res < 0)
				{
						debug_printf(LOG_LEVEL_BASIC,"get_route_info error snmp_ip=%s\n",session.peername);
						snmp_close(ss); 
						return NULL;
				}
		}

		//上报路由信息
		update_route_info(snmp_node->snmp.name,route);

		vector<IpMac>arp_map;	
		SysInfo sys;

		arg_name_t sys_arg[] = {{LOAD,".1.3.6.1.4.1.2021.10.1.5.3"},{USERCPU,".1.3.6.1.4.1.2021.11.9.0"},{SYSCPU,".1.3.6.1.4.1.2021.11.10.0"},{IDLECPU,".1.3.6.1.4.1.2021.11.11.0"},{TOTALMEM,".1.3.6.1.4.1.2021.4.5.0"},{FREEMEM,".1.3.6.1.4.1.2021.4.6.0"},{BUFFER,".1.3.6.1.4.1.2021.4.14.0"},{CACHE,".1.3.6.1.4.1.2021.4.15.0"}};
		//arg_name_t sys_arg[] = {{LOAD,"laLoadInt.2"},{USERCPU,"ssCpuUser.0"},{SYSCPU,"ssCpuSystem.0"},{IDLECPU,"ssCpuIdle.0"},{TOTALMEM,"memTotalReal.0"},{FREEMEM,"memAvailReal.0"},{BUFFER,"memBuffer.0"},{CACHE,"memCached.0"}};

		arg_name_t traffic_arg[] = {{TRAFFIC_OUT,".1.3.6.1.2.1.2.2.1.16"},{TRAFFIC_IN,".1.3.6.1.2.1.2.2.1.10"}};
		//arg_name_t traffic_arg[] = {{TRAFFIC_OUT,"ifOutOctets"},{TRAFFIC_IN,"ifInOctets"}};
		
		while(thread_exit_flag)
		{
				//if(false == client_connecting_flag || 1 != primary_flag || false == snmp_node->snmp.enable)
				if(false == client_connecting_flag || false == snmp_node->snmp.enable)
				{
						sleep(1);
						continue;
				}
				
				arp_map.clear();
				res = get_arp_map(snmp_node->snmp,arp_map);
				if(res < 0)
				{
						debug_printf(LOG_LEVEL_BASIC,"get_interface_ip_mac error snmp_ip=%s\n",session.peername);
						snmp_close(ss); 
						return NULL;
				}

				//此处上报经过端口的ip和mac地址
				update_interface_ipmac(snmp_node->snmp.name,arp_map);

				res = get_sys_info(ss,sys,sizeof(sys_arg)/sizeof(sys_arg[0]),sys_arg);
				if(res < 0)
				{
						debug_printf(LOG_LEVEL_BASIC,"get_sys_info error snmp_ip=%s\n",session.peername);
						snmp_close(ss); 
						return NULL;
				}
				sys.availmem = sys.freemem + sys.buffer + sys.cache;

				// 上报系统信息
				update_sys_info(snmp_node->snmp.name,sys);		

				if(!snmp_node->process.empty())
				{
						// 上报进程信息
						update_snmp_node_process(ss,snmp_node,snmp_node->process);
				}

				eth_traffic.assign(eth_num,tmp_eth_traffic);
				res = get_interface_traffic(ss,eth_traffic,eth_num,eth_index,traffic_arg[0]);
				if(res < 0)
				{
						debug_printf(LOG_LEVEL_BASIC,"get_interface_info error snmp_ip=%s\n",session.peername);
						snmp_close(ss); 
						return NULL;
				}
				res = get_interface_traffic(ss,eth_traffic,eth_num,eth_index,traffic_arg[1]);
				if(res < 0)
				{
						debug_printf(LOG_LEVEL_BASIC,"get_interface_info error snmp_ip=%s\n",session.peername);
						snmp_close(ss); 
						return NULL;
				}
				//上报流量
				update_interface_traffic(snmp_node->snmp.name,eth_traffic);

				sleep(snmp_node->snmp.interval);
#if 0	
				memset(traffic_start_out,0,sizeof(traffic_start_out));
				memset(traffic_end_out,0,sizeof(traffic_end_out));
				memset(traffic_start_in,0,sizeof(traffic_start_in));
				memset(traffic_end_in,0,sizeof(traffic_end_in));
				memset(eth_traffic,0,sizeof(eth_traffic));
				res = get_interface_traffic(ss,traffic_start_out,eth_num,eth_index,traffic_arg[0]);
				res = get_interface_traffic(ss,traffic_start_in,eth_num,eth_index,traffic_arg[1]);
				sleep(snmp_node->snmp.interval);
				res = get_interface_traffic(ss,traffic_end_out,eth_num,eth_index,traffic_arg[0]);
				res = get_interface_traffic(ss,traffic_end_in,eth_num,eth_index,traffic_arg[1]);

				for(i = 0 ; i < eth_num ; i++)
				{
						eth[i].index = eth_index[i];
						eth_traffic[i].index = eth_index[i];

						outoctets = traffic_end_out[i].outoctets - traffic_start_out[i].outoctets;

						if(outoctets < 0)
						{
								outoctets = max_int - traffic_start_out[i].outoctets + traffic_end_out[i].outoctets;
						}

						eth_traffic[i].traffic.outoctets = outoctets / snmp_node.interval;

						inoctets = traffic_end_in[i].inoctets - traffic_start_in[i].inoctets;

						if(inoctets < 0)
						{
								inoctets = max_int - traffic_start_in[i].inoctets + traffic_end_in[i].inoctets;
						}

						eth_traffic[i].traffic.inoctets = inoctets / snmp_node.interval;
				}
#endif
				//此处上报端口流量
				
		}

		snmp_close(ss); 
		return NULL;

}




