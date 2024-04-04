CC=gcc
CFLAGS=-Wall
LDFLAGS=-lnetfilter_queue

all: netfilter-test

netfilter-test: netfilter-test.c
	$(CC) $(CFLAGS) -o netfilter-test netfilter-test.c $(LDFLAGS)

clean:
	rm -f netfilter-test

