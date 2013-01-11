DEFINES=-D_GNU_SOURCE -DUNBOUND_CONFIG_FILE=\"/etc/unbound/unbound.conf\"
CFLAGS=-c -W -Wall -Wextra -Werror -pedantic -std=c99 -fPIC -g -rdynamic $(DEFINES)
LDFLAGS=-shared -lunbound
SPLINTFLAGS=+posixlib -boolops

SRCS=unbify.c getaddrinfo.c dlfunc.c
OBJS=$(SRCS:.c=.o)

all: libunbify.so

%.o: %.c
	$(CC) $(CFLAGS) $< -o $@

libunbify.so: $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^

.PHONY: splint install clean
splint:
	splint $(SPLINTFLAGS) $(DEFINES) $(SRCS)

clean:
	rm -f *.o
	rm -f *.so
