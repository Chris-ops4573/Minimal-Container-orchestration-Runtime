CC=gcc
CFLAGS=-Wall
LIBS=-lpthread -lseccomp -lcap -lcrypt

all: server client

server: server.c auth.c container.c logger.c
	$(CC) $(CFLAGS) $^ -o server $(LIBS)

client: client.c
	$(CC) $(CFLAGS) $^ -o client

clean:
	rm -f server client *.o