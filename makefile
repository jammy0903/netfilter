# Makefile

CC=gcc
CFLAGS=-Wall
LIBS=-lnetfilter_queue
TARGET=nfqnl_test
SOURCE=nfqnl_test.c

all: $(TARGET)

$(TARGET): $(SOURCE)
	$(CC) $(CFLAGS) -o $(TARGET) $(SOURCE) $(LIBS)

clean:
	rm -f $(TARGET)

