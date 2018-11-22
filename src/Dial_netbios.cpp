#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "Dial_netbios.h"



int generate_netbios_packet(unsigned char *pnetbios_buf,int buf_size)
{
#if 1
		unsigned char buf[] = {0,0,0,0x23,0xff,0x53,0x4d,0x42,0x72,0,0,0,0,0x08,0x01,0xc8,
				0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};

		memcpy(pnetbios_buf,buf,sizeof(buf));
		unsigned short pid = htons(getpid());
		memcpy(pnetbios_buf+30,&pid,sizeof(unsigned short));

        return sizeof(buf);
#endif

#if 0
		unsigned char * p_begin = pnetbios_buf;
		unsigned char * p_end = pnetbios_buf;
		unsigned char * p_data_len = pnetbios_buf + 2;

#endif

}
