#pragma once

#define MAX_DEBUG_BUFFER_LEN  			        4096
#define MAX_DEBUG_FILE_SIZE  			        1024*1024*50

#define DEBUG_LOG_FILE_PATH  			       "/var/log/"
#define DEBUG_LOG_FILE_DIAL  					"dial.log"
#define CONFIG_LOG_FILE_DIAL  				"dial_cfg.log"


enum LOG_LEVEL {
	LOG_LEVEL_TEST = 1,
	LOG_LEVEL_BASIC = 2,
	LOG_LEVEL_DEBUG = 3,
	LOG_LEVEL_ERROR = 4,
};

enum LOG_TYPE{
	LOG_RUN=1,
	LOG_CONFIG=2,
};


int
log_printf(int level,int type,const char *logfile,const char * fmt,...);

int
write_debug_file(unsigned char			*filename,
					unsigned char			*buffer);

