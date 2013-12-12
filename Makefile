# Makefile for transconnect

CFLAGS  = -Wall -fPIC
LDFLAGS = -shared
LINUX_LDLIBS  = -ldl

SUN_LDFLAGS   = -G
SUN_LDLIBS    = -lsocket -lnsl

all: tconn.so tconn-localres.so tconn-tcpdns.so tconn-localtcp.so

tconn.so: tconn.c
	$(CC) $(CFLAGS) $(LDFLAGS) $(LINUX_LDLIBS) -o tconn.so tconn.c

tconn-localres.so: tconn.c
	$(CC) $(CFLAGS) $(LDFLAGS) $(LINUX_LDLIBS) -D USE_LOCAL_RESOLV_CONF -o tconn-localres.so tconn.c

tconn-tcpdns.so: tconn.c
	$(CC) $(CFLAGS) $(LDFLAGS) $(LINUX_LDLIBS) -D USE_TCP_FOR_DNS -o tconn-tcpdns.so tconn.c

tconn-localtcp.so: tconn.c
	$(CC) $(CFLAGS) $(LDFLAGS) $(LINUX_LDLIBS) -D USE_LOCAL_RESOLV_CONF -D USE_TCP_FOR_DNS -o tconn-localtcp.so tconn.c

bsd: tconn.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o tconn.so tconn.c -D_BSD_HACK_

sun: tconn.c
	$(CC) $(SUN_LDFLAGS) $(SUN_LDLIBS) -o tconn.so tconn.c

install:
	mkdir -p $(HOME)/.tconn
	chmod 700 $(HOME)/.tconn
	cp -f tconn*so $(HOME)/.tconn/
	cp -f --backup=t -S .bak tconn.conf $(HOME)/.tconn/
	cp -f README $(HOME)/.tconn/
	cp -f INSTALL $(HOME)/.tconn/
	cat tconn.cat

clean:
	rm -f tconn*so
	   
.PHONY: clean
