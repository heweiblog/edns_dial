#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/time.h>

#include "Dial_mode.h"
#include "Dial_smtp.h"
#include "Dial_common.h"

static char base64_table[64] =
{
		'A', 'B', 'C', 'D', 'E', 'F', 'G',
		'H', 'I', 'J', 'K', 'L', 'M', 'N',
		'O', 'P', 'Q', 'R', 'S', 'T',
		'U', 'V', 'W', 'X', 'Y', 'Z',
		'a', 'b', 'c', 'd', 'e', 'f', 'g',
		'h', 'i', 'j', 'k', 'l', 'm', 'n',
		'o', 'p', 'q', 'r', 's', 't',
		'u', 'v', 'w', 'x', 'y', 'z',
		'0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
		'+', '/'
};

int base64_encode(unsigned char* pBase64, int nLen, char* pOutBuf, int nBufSize)
{
		int i = 0;
		int j = 0;
		int nOutStrLen = 0;

		/* nOutStrLen does not contain null terminator. */
		nOutStrLen = nLen / 3 * 4 + (0 == (nLen % 3) ? 0 : 4);
		if ( pOutBuf && nOutStrLen < nBufSize )
		{
				char cTmp = 0;
				for ( i = 0, j = 0; i < nLen; i += 3, j += 4 )
				{
						/* the first character: from the first byte. */
						pOutBuf[j] = base64_table[pBase64[i] >> 2];

						/* the second character: from the first & second byte. */
						cTmp = (char)((pBase64[i] & 0x3) << 4);
						if ( i + 1 < nLen )
						{
								cTmp |= ((pBase64[i + 1] & 0xf0) >> 4);
						}
						pOutBuf[j+1] = base64_table[(int)cTmp];

						/* the third character: from the second & third byte. */
						cTmp = '=';
						if ( i + 1 < nLen )
						{
								cTmp = (char)((pBase64[i + 1] & 0xf) << 2);
								if ( i + 2 < nLen )
								{
										cTmp |= (pBase64[i + 2] >> 6);
								}
								cTmp = base64_table[(int)cTmp];
						}
						pOutBuf[j + 2] = cTmp;

						/* the fourth character: from the third byte. */
						cTmp = '=';
						if ( i + 2 < nLen )
						{
								cTmp = base64_table[pBase64[i + 2] & 0x3f];
						}
						pOutBuf[j + 3] = cTmp;
				}

				pOutBuf[j] = '\0';
		}

		return nOutStrLen + 1;
}

int handle_smtp_dialing(const char*ip,const int port,int* delay)
{
		int rtn = 0;
		struct timeval t_start;
		struct timeval t_end;
		char recv_buf[1024] = {'\0'};
		char user64[512] = {0};
		char pass64[512] = {0};

		int fd = create_tcp_client_socket_fd();
		if(fd <= 0) 
		{
				debug_printf(LOG_LEVEL_ERROR,"handle_smtp_dialing:create fd failed!!!ip=%s\n",ip);
				return ERROR;
		}

		gettimeofday(&t_start,NULL);

		if(build_tcp_connection(fd,port,(char*)ip) < 0) 
		{
				debug_printf(LOG_LEVEL_ERROR,"%s-%d-handle_smtp_dialing:connect fd failed!!!ip=%s,port=%d\n",__func__,__LINE__,ip,port);
				close(fd);
				return ERROR;
		}

		memset(recv_buf,0,1024);
		rtn = recv(fd,recv_buf,1024,0);
		if(rtn < 0)
		{
				debug_printf(LOG_LEVEL_ERROR,"%s-%d-handle_smtp_dialing:recv failed!!!ip=%s,port=%d\n",__func__,__LINE__,ip,port);
		}
		else
		{
				if(strstr(recv_buf,"220"))
				{
						gettimeofday(&t_end,NULL);
						*delay = ((t_end.tv_sec * 1000*1000 + t_end.tv_usec) - (t_start.tv_sec * 1000*1000 + t_start.tv_usec));
						debug_printf(LOG_LEVEL_DEBUG,"%s-%d-handle_smtp_dialing:success!!!ip=%s,port=%d\n",__func__,__LINE__,ip,port);
						close(fd);
						return NO_ERROR;
				}
		}

		char buffer[] = "ehlo localhost\r\n";
		rtn = send(fd, buffer, strlen(buffer), 0);
		if(rtn < 0)
		{
				debug_printf(LOG_LEVEL_ERROR,"%s-%d-handle_smtp_dialing:send failed!!!ip=%s,port=%d\n",__func__,__LINE__,ip,port);
				close(fd);
				return ERROR;
		}

		memset(recv_buf,0,1024);
		rtn = recv(fd,recv_buf,1024,0);
		if(rtn < 0)
		{
				debug_printf(LOG_LEVEL_ERROR,"%s-%d-handle_smtp_dialing:recv failed!!!ip=%s,port=%d\n",__func__,__LINE__,ip,port);
				close(fd);
				return ERROR;
		}

		close(fd);

		if(strstr(recv_buf,"220") || strstr(recv_buf,"250"))
		{
				gettimeofday(&t_end,NULL);
				*delay = ((t_end.tv_sec * 1000*1000 + t_end.tv_usec) - (t_start.tv_sec * 1000*1000 + t_start.tv_usec));
				debug_printf(LOG_LEVEL_DEBUG,"%s-%d-handle_smtp_dialing:success!!!ip=%s,port=%d\n",__func__,__LINE__,ip,port);
				return NO_ERROR;
		}

		debug_printf(LOG_LEVEL_DEBUG,"%s-%d-handle_smtp_dialing:failed!!!ip=%s,port=%d\n",__func__,__LINE__,ip,port);
		return ERROR;
}


#if 0
int handle_smtp_dialing(const char*ip,const char* user,const char* pass,const int port,int* delay)
{
		int rtn = 0;
		struct timeval t_start;
		struct timeval t_end;
		char recv_buf[1024] = {'\0'};
		char user64[512] = {0};
		char pass64[512] = {0};

		int fd = create_tcp_client_socket_fd();
		if(fd <= 0) 
		{
				debug_printf(LOG_LEVEL_ERROR,"handle_smtp_dialing:create fd failed!!!ip=%s\n",ip);
				return ERROR;
		}

		gettimeofday(&t_start,NULL);

		if(build_tcp_connection(fd,port,(char*)ip) < 0) 
		{
				debug_printf(LOG_LEVEL_ERROR,"%s-%d-handle_smtp_dialing:connect fd failed!!!ip=%s,port=%d\n",__func__,__LINE__,ip,port);
				close(fd);
				return ERROR;
		}

		memset(recv_buf,0,1024);
		rtn = recv(fd,recv_buf,1024,0);
		if(rtn < 0)
		{
				debug_printf(LOG_LEVEL_ERROR,"%s-%d-handle_smtp_dialing:recv failed!!!ip=%s,port=%d\n",__func__,__LINE__,ip,port);
				close(fd);
				return ERROR;
		}

		char buffer[] = "ehlo localhost\r\n";
		rtn = send(fd, buffer, strlen(buffer), 0);
		if(rtn < 0)
		{
				debug_printf(LOG_LEVEL_ERROR,"%s-%d-handle_smtp_dialing:send failed!!!ip=%s,port=%d\n",__func__,__LINE__,ip,port);
				close(fd);
				return ERROR;
		}

		memset(recv_buf,0,1024);
		rtn = recv(fd,recv_buf,1024,0);
		if(rtn < 0)
		{
				debug_printf(LOG_LEVEL_ERROR,"%s-%d-handle_smtp_dialing:recv failed!!!ip=%s,port=%d\n",__func__,__LINE__,ip,port);
				close(fd);
				return ERROR;
		}

		char bufferLogin[] = "auth login\r\n";
		rtn = send(fd, bufferLogin, strlen(bufferLogin),0);
		if(rtn < 0)
		{
				debug_printf(LOG_LEVEL_ERROR,"%s-%d-handle_smtp_dialing:send failed!!!ip=%s,port=%d\n",__func__,__LINE__,ip,port);
				close(fd);
				return ERROR;
		}

		memset(recv_buf,0,1024);
		rtn = recv(fd,recv_buf,1024,0);
		if(rtn < 0)
		{
				debug_printf(LOG_LEVEL_ERROR,"%s-%d-handle_smtp_dialing:recv failed!!!ip=%s,port=%d\n",__func__,__LINE__,ip,port);
				close(fd);
				return ERROR;
		}

		base64_encode((unsigned char*)user,strlen(user),user64,512);
		strcat(user64,"\r\n");
		base64_encode((unsigned char*)pass,strlen(pass),pass64,512);
		strcat(pass64,"\r\n");

		rtn = send(fd,user64, strlen(user64),0);
		if(rtn < 0)
		{
				debug_printf(LOG_LEVEL_ERROR,"%s-%d-handle_smtp_dialing:send failed!!!ip=%s,port=%d\n",__func__,__LINE__,ip,port);
				close(fd);
				return ERROR;
		}

		memset(recv_buf,0,1024);
		rtn = recv(fd,recv_buf,1024,0);
		if(rtn < 0)
		{
				debug_printf(LOG_LEVEL_ERROR,"%s-%d-handle_smtp_dialing:recv failed!!!ip=%s,port=%d\n",__func__,__LINE__,ip,port);
				close(fd);
				return ERROR;
		}

		rtn = send(fd,pass64, strlen(pass64),0);

		memset(recv_buf,0,1024);
		rtn = recv(fd,recv_buf,1024,0);
		if(rtn < 0)
		{
				debug_printf(LOG_LEVEL_ERROR,"%s-%d-handle_smtp_dialing:recv failed!!!ip=%s,port=%d\n",__func__,__LINE__,ip,port);
				close(fd);
				return ERROR;
		}

		close(fd);

		if(strstr(recv_buf,"successful"))
		{
				gettimeofday(&t_end,NULL);
				*delay = ((t_end.tv_sec * 1000*1000 + t_end.tv_usec) - (t_start.tv_sec * 1000*1000 + t_start.tv_usec));
				debug_printf(LOG_LEVEL_DEBUG,"handle_smtp_dialing:success!!!ip=%s,port=%d\n",__func__,__LINE__,ip,port);
				return NO_ERROR;
		}

		debug_printf(LOG_LEVEL_DEBUG,"%s-%d-handle_smtp_dialing:failed!!!ip=%s,port=%d\n",__func__,__LINE__,ip,port);
		return ERROR;
}
#endif
