build: 
	gcc -Wall client.c -o client
	gcc -Wall server.c -o server
clean: 
	rm client server
clean_log: 
	rm *.log
