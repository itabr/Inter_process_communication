# declare variable
C = gcc
CFLAGS= -Wall -lmcrypt -pthread -o 
# build an executable named test from test.c
all: server.c client.c
	@$(C) $(CFLAGS) server -g server.c
	@$(C) $(CFLAGS) client -g client.c

server: server.c
	@$(C) $(CFLAGS) server -g server.c

client: client.c
	@$(C) $(CFLAGS) client -g client.c

# remove the executable named test
clean: 
	@$(RM) server
	@$(RM) client
	@$(RM) *.o

dist:
	@$ rm -rf lab1b.tar.gz
	@$ tar -cvzf lab1b.tar.gz server.c client.c Makefile README my.key