CC      = gcc
CFLAGS  = -Wall -Wunused -Wstrict-prototypes -g -O2
INCLUDE = -I.. -I.
LIBS	= -lpopt

forwarder:	forwarder.c
		$(CC) $(CFLAGS) $(INCLUDE) $(LIBS) -o $@ $^

clean:
		rm -f forwarder *.o *~ *.orig
