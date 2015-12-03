# Makefile for micro_proxy

# CONFIGURE: If you are using a SystemV-based operating system, such as
# Solaris, you will need to uncomment this definition.
#SYSV_LIBS =	-lnsl -lsocket


BINDIR =	/usr/local/sbin
MANDIR =	/usr/local/man/man8
CC =		cc
CFLAGS =	-O -ansi -pedantic -U__STRICT_ANSI__ -Wall -Wpointer-arith -Wshadow -Wcast-qual -Wcast-align -Wstrict-prototypes -Wmissing-prototypes -Wmissing-declarations -Wredundant-decls -Wno-long-long
LDFLAGS =	$(SYSV_LIBS)

all:		micro_proxy

micro_proxy:	micro_proxy.o
	$(CC) micro_proxy.o $(LDFLAGS) -o micro_proxy

micro_proxy.o:	micro_proxy.c
	$(CC) $(CFLAGS) -c micro_proxy.c

install:	all
	rm -f $(BINDIR)/micro_proxy
	cp micro_proxy $(BINDIR)
	rm -f $(MANDIR)/micro_proxy.8
	cp micro_proxy.8 $(MANDIR)

clean:
	rm -f micro_proxy *.o core core.* *.core
