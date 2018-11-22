
TGT=client
SRCS=$(wildcard *.cpp)

LIBS= -levent -lrt -pthread -lssl -lcrypto -ldl -lz  -lthriftnb -lthrift
CFLAGS= -g -W -O2 -DHAVE_NETINET_IN_H -I./include -I/glib-2.0 -I/usr/lib64/glib-2.0/include/ -I/usr/include/openssl

CC=g++

all:$(TGT)
	@echo Generation target!	

$(TGT):$(SRCS:.cpp=.o)
	$(CC) -o $@ $^ $(LIBS) $(CFLAGS) 
	
%.o : %.cpp
	$(CC) -c $(CFLAGS) $< -o $@
	
.PHONY:	clean rpmclean 

clean:
	rm -rf $(TGT) $(SRCS:.cpp=.o)

