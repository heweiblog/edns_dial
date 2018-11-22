#ifndef DIAL_ICMP_H
#define DIAL_ICMP_H

#define E_FAILD_FD -1
#define ICMP_DATA_LEN 20 
#define ICMP_BUFF_LEN 128  
#define ICMP_ECHO_MAX 4  
#define ICMP_REQUEST_TIMEOUT 2  

int create_client_raw_socket();

int new_icmp_echo(const int iPacketNum, unsigned char *aucSendBuf,const int iDataLen);

int sendIcmp(const int fd, const char *dip);

//int ipsec_ping(const int fd,uint32_t dip,int iPktLen,unsigned char *aucSendBuf);
int ipsec_ping(const int fd,uint32_t dip);

void* ipsec_work_thread(void * arg);

#endif




