# tcpsf:  tcp splicing module for the Linux kernel

NAME	= tcpsp
VERSION = 0.0.5

# uncomment the following line on an SMP system
#SMPFLAGS= -D__SMP__

# uncomment the following line for DEBUG
DEBUGFLAGS= -DCONFIG_TCPSP_DEBUG -g


CC=gcc
CFLAGS= -D__KERNEL__ -DMODULE -DEXPORT_SYMTAB -DMODVERSIONS \
	$(SMPFLAGS) $(DEBUGFLAGS) -O2 -Wall \
	-Wstrict-prototypes -I/usr/src/linux/include \
	-include /usr/src/linux/include/linux/modversions.h

all:	tcpsp.o

tcpsp.o:	 tcpsp_ctl.o tcpsp_core.o tcpsp_conn.o
	$(LD) -r $^ -o $@

install:	tcpsp.o
	-rmmod tcpsp
	insmod tcpsp.o
	lsmod

clean:
	rm -f *.o *~ *.bak *.orig *.rej $(NAME)-$(VERSION).tar.gz

distclean: clean
	rm -f TAGS
	make clean -C example

dist:	distclean
	(cd .. ; tar czvf $(NAME)-$(VERSION).tar.gz --exclude CVS tcpsp)
	mv ../$(NAME)-$(VERSION).tar.gz .
