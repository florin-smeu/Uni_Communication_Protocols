# Copyright 2018 Florin-Ion Smeu (florin.ion.smeu@gmail.com)

CC = gcc
SRC = dnsclient.c
EXEC = dnsclient
MSG_LOG = message.log
DNS_LOG = dns.log
ARG1 = www.google.com
ARG2 = A

build: $(SRC)
	$(CC) $(SRC) -o $(EXEC)

run: $(EXEC)
	./$(EXEC) $(ARG1) $(ARG2)	

clean:
	rm $(EXEC) $(MSG_LOG) $(DNS_LOG)
