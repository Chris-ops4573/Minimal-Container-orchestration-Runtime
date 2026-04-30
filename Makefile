CC=gcc
CFLAGS=-Wall
LIBS=-lpthread -lseccomp -lcap -lcrypt

all: server client breakout

server: server.c auth.c container.c logger.c
	$(CC) $(CFLAGS) $^ -o server $(LIBS)

client: client.c
	$(CC) $(CFLAGS) $^ -o client

breakout: test_dir/breakout.c
	$(CC) $(CFLAGS) $^ -o test_dir/breakout

clean:
	rm -f server client test_dir/breakout *.o