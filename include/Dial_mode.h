#ifndef DIAL_MODE_
#define DIAL_MODE_
#include "Dial_server.h"


int handle_icmp_dialing(char *dip,int * delay);


int handle_tcp_and_port_dialing(char *ip,int port,int * delay);


int handle_httpget_dialing(char *ip,int port,char *resource,char *host,int * delay);


int handle_httpget_dialing2(char *ip,int port,char *resource,char *host,dial_option_t *option);


int handle_httpsget_dialing(char *ip,int port,char *resource,char *host,int * delay);


int handle_exthttpget_dialing(char *ip,char *host,dial_option_t *option,int * delay);


int handle_icmp_dialing(char *dip,int * delay);


int handle_db_dialing(char *ip,char *url,char *db_cmd,int * delay);


int handle_netbios_dialing(char *ip,int port,int * delay);


int create_tcp_client_socket_fd();


int build_tcp_connection(int fd,int port,char *ip);


int handle_ext_tcp_and_port_dialing(char *ip,healthpolicy_info_t *policy,int * delay);


int create_pattern(char *str,char *pattern);


int check_httpget_result(dial_option_t *option,char *src,char *pattern,unsigned int code);


int handle_udp_and_port_dialing(char *ip,int port,int * delay);


#endif
