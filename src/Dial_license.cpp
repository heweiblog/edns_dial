#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <fcntl.h>

#include <openssl/sha.h>

#include "Dial_common.h"
#include "Dial_license.h"


int devinfo_get(char *str, int len)
{
		char buff[SHA_BUFF_SIZE]  = {0};
		char cpu_buff[SHA_BUFF_SIZE]  = {0};
		int fd;
		char *offset = buff;
		int ret = 0;
		char *cpu_v = NULL;
		char *t = NULL;
		char sha[SHA_BUFF_SIZE] = {0};
		int i = 0;
		int *s;

		if(len < SHA_SIZE)
				return -1;

		//主板名
		fd = open("/sys/class/dmi/id/board_name",O_RDONLY,0);
		if(fd == -1) 
		{
				cfg_debug_printf(LOG_LEVEL_BASIC,"get board_name error!\n");
				return -1;
		}
		ret = read(fd, offset, SHA_BUFF_SIZE - (offset - buff));
		//cfg_debug_printf(LOG_LEVEL_BASIC,"board_name = %s\n",offset);
		close(fd);
		offset += ret;

		//主板序列号
		fd = open("/sys/class/dmi/id/board_serial",O_RDONLY,0);
		if(fd == -1) 
		{
				cfg_debug_printf(LOG_LEVEL_BASIC,"get board_serial error!\n");
				return -1;
		}
		ret = read(fd, offset, SHA_BUFF_SIZE - (offset - buff));
		//cfg_debug_printf(LOG_LEVEL_BASIC,"board_serial = %s\n",offset);
		close(fd);
		offset += ret;

		//系统uuid
		fd = open("/sys/class/dmi/id/product_uuid",O_RDONLY,0);
		if(fd == -1) 
		{
				cfg_debug_printf(LOG_LEVEL_BASIC,"get product_uuid error!\n");
				return -1;
		}
		ret = read(fd, offset, SHA_BUFF_SIZE - (offset - buff));
		//cfg_debug_printf(LOG_LEVEL_BASIC,"product_uuid = %s\n",offset);
		close(fd);
		offset += ret;

		//cpu型号
		fd = open("/proc/cpuinfo",O_RDONLY,0);
		if(fd == -1) 
		{
				cfg_debug_printf(LOG_LEVEL_BASIC,"get cpuinfo error!\n");
				return -1;
		}
		read(fd, cpu_buff, SHA_BUFF_SIZE);
		cpu_v = strstr(cpu_buff,"model name");
		if(cpu_v == NULL)
		{
				cfg_debug_printf(LOG_LEVEL_BASIC,"analysis cpuinfo error!\n");
				return -1;
		}

		t = cpu_v + 12; // 跳过 ‘model name : ’
		while(*t != '\n')
		{
				t++;
		}

		if((t - cpu_v) > (SHA_BUFF_SIZE - (offset - buff))) //防止越界
		{
				cfg_debug_printf(LOG_LEVEL_BASIC,"cpu version string too long!\n");
				return -1;
		}

		sscanf(cpu_v + 12,"%[^\n]",offset);//读取到换行\n
		//cfg_debug_printf(LOG_LEVEL_BASIC,"cpu version = %s\n",offset);
		close(fd);

		SHA1((const unsigned char*)buff,((offset + (t - cpu_v)) - buff),(unsigned char*)sha);

		memcpy(str,sha,SHA_SIZE);

		return 0;
}


void sha_to_str(char*sha)
{
		char buf[10] = {'\0'};
		char tmp[50] = {'\0'};
		int *s = NULL;
		int i = 0;
		s = (int *)sha;
		while(i < 5){ //20个字节
				memset(buf,0,10);
				sprintf(buf,"%x",*s);
				strcat(tmp,buf);
				i++;
				s++;
		}
		strcpy(sha,tmp);
}

