#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>

#define BUFLEN 256
#define N_ARGS 3
#define LOG_NAME_LEN 32
#define CARD_LEN 6

void error(char *msg)
{
	perror(msg);
	exit(0);
}

void usage(char*file)
{
	fprintf(stderr,"Usage: %s ip_server port_server\n",file);
	exit(0);
}

/*
 * Functia realizeaza inchiderea socket-urilor, cat si a fisierului log. 	
 */
void close_all(fd_set *read_fds, int fdmax, int udp_sockfd, FILE *log) 
{
	for (int i = 0; i <= fdmax; ++i) {
			close(i);
			FD_CLR(i, read_fds);
	}
	close(udp_sockfd);
	fflush(log);
	fclose(log);		
}

int main(int argc, char *argv[])
{
	if (argc != N_ARGS) usage(argv[0]);
	
	// Creare fisier log
	char filename[LOG_NAME_LEN];
	sprintf(filename, "client-%d.log", getpid()); 	
	FILE *log = fopen(filename, "wt");
	
	// Deschidere socketi TCP si UDP	
	int tcp_sockfd, udp_sockfd;
	tcp_sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (tcp_sockfd < 0) error("EROARE deschidere socket TCP");
	udp_sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (udp_sockfd < 0) error("EROARE deschidere socket UDP");
	
	// Completare informatii adresa server
	struct sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_port = htons(atoi(argv[2]));
	inet_aton(argv[1], &addr.sin_addr);

	// Conectare clienti la server
	if (connect(tcp_sockfd, (struct sockaddr *) &addr,
				sizeof(struct sockaddr)) < 0) error ("EROARE conectare TCP");
		
	fd_set read_fds, tmp_fds;
	int fdmax;
	if (tcp_sockfd > udp_sockfd) fdmax = tcp_sockfd;
	else fdmax = udp_sockfd;
	FD_ZERO(&read_fds);
	FD_ZERO(&tmp_fds);
	FD_SET(tcp_sockfd, &read_fds);
	FD_SET(STDIN_FILENO, &read_fds);

	// Retinem ultimul card pentru care s-a incercat login,
	// cat si daca avem vreun client logat 
	char buffer[BUFLEN];
	char last_login_card[CARD_LEN] = "000000";
	int logged = 0;

	while(1) {
		tmp_fds = read_fds;
			
		// Multiplexare
		if (select(fdmax + 1, &tmp_fds, NULL, NULL, NULL) < 0) 
			error("EROARE select");

		for (int i = 0; i <= fdmax; ++i) {
			if (FD_ISSET(i, &tmp_fds)) {
				if (i == STDIN_FILENO) {
					// Clientul primeste comenzi de la tastatura
					memset(buffer, 0, BUFLEN);
					fgets(buffer, BUFLEN - 1, stdin);
					fprintf(log, "%s", buffer);
					fflush(log);	
					// Verificam daca se doreste inchiderea clientului
					if (strncmp(buffer, "quit", 4) == 0) {
						send(tcp_sockfd, buffer, strlen(buffer) + 1, 0);
						close_all(&read_fds, fdmax, udp_sockfd, log);				
						return 0;
					}
					// Clientul comunica serverului pe socketul UDP
					
					// Se doreste deblocarea contului
					if (strncmp(buffer, "unlock", 6) == 0) {
						// Adaugam numarul cardului la mesajul trimis
						sprintf(buffer, "unlock %s", last_login_card);
						if (sendto(udp_sockfd, buffer, strlen(buffer) + 1, 0,
							   (struct sockaddr *) &addr, 
							   sizeof (struct sockaddr)) < 0) {
							close_all(&read_fds, fdmax, udp_sockfd, log);
							return 0;
						}
					
						memset(buffer, 0, BUFLEN);
						struct sockaddr_in udp_aux_addr;
						unsigned int addr_len = sizeof(struct sockaddr);

						if (recvfrom(udp_sockfd, buffer, BUFLEN, 0, 
								 (struct sockaddr *) &udp_aux_addr,
								  &addr_len) == -1) {
							close_all(&read_fds, fdmax, udp_sockfd, log);
							return 0;	
						} 
						printf("%s\n", buffer);			
						fprintf(log, "%s\n", buffer);
						
						// Este solicitata introducerea parolei secrete
						if (strcmp(buffer,
								   "UNLOCK> Trimite parola secreta") == 0) {
							memset(buffer, 0, BUFLEN);
							fgets(buffer, BUFLEN - 1, stdin);
							if (sendto(udp_sockfd, buffer, strlen(buffer) + 1,
									   0, (struct sockaddr *) &addr, 
									   sizeof(struct sockaddr)) == -1) {
								close_all(&read_fds, fdmax, udp_sockfd, log);
								return 0;
							}
							fprintf(log, "%s", buffer);
							if (recvfrom(udp_sockfd, buffer, BUFLEN, 0, 
								 (struct sockaddr *) &udp_aux_addr,
								  &addr_len) == -1) {
								close_all(&read_fds, fdmax, udp_sockfd, log);
								return 0;	
							}
							printf("%s\n", buffer);
							fprintf(log, "%s\n", buffer);
							fflush(log);
						} 
						continue;
					}	
					// Clientul comunica serverului pe socketul TCP
					
					// Se incearca deschiderea unei noi sesiuni pentru 
					// un cont deja logat
					if (logged == 1 && strncmp(buffer, "login", 6) == 0) {
						printf("-2 : Sesiune deja deschisa\n");
						fprintf(log, "-2 : Sesiune deja deschisa\n");
						fflush(log);
						continue;
					}
					// Se apeleaza o comanda care necesita logarea prealabila
					if (logged == 0 && strncmp(buffer, "login", 5) != 0) {
						printf("-1 : Clientul nu este autentificat\n");
						fprintf(log, "-1 : Clientul nu este autentificat\n");
						fflush(log);
						continue;
					}	
						
					char aux_buffer[BUFLEN];
					strcpy(aux_buffer, buffer);	
	 				char *tk1 = strtok(buffer, " \n");
					// Se doreste logarea 	
					if (strcmp(tk1, "login") == 0) {
						char *tk2 = strtok(NULL, " \n");
						strncpy(last_login_card, tk2, 6);
					}			
					strcpy(buffer, aux_buffer);	

					if (send(tcp_sockfd, buffer, strlen(buffer) + 1, 0) <= 0) {
						fprintf(log, "%s", buffer); 
						close_all(&read_fds, fdmax, udp_sockfd, log);
						return 0;
					}
				} else if (i == tcp_sockfd) {
					// Clientul primeste mesaje pe socketul TCP
					memset(buffer, 0, BUFLEN);
					if (recv(tcp_sockfd, buffer, BUFLEN, 0) <= 0) {
						close_all(&read_fds, fdmax, udp_sockfd, log);
						return 0;
					}
					printf("%s\n", buffer);				
					fprintf(log, "%s\n", buffer);
					fflush(log);
					// Logarea a avut loc cu succes
					if (strncmp(buffer, "IBANK> Welcome", 14) == 0) logged = 1; 
					// Sesiunea curenta trebuie inchisa
					if (strcmp(buffer, "IBANK> Clientul a fost deconectat") 
						== 0) logged = 0;
					// Trebuie confirmat transferul
					if (strstr(buffer, "[y/n]") != 0) {
						fgets(buffer, BUFLEN - 1, stdin);
						if (send(tcp_sockfd, buffer, strlen(buffer) + 1, 0) 
							<= 0) {
							close_all(&read_fds, fdmax, udp_sockfd, log);
							return 0;
						}	
						fprintf(log, "%s", buffer);
						fflush(log);
					}
					
				} else {
					// Inchiderea serverului va implica inchiderea clientului
					memset(buffer, 0, BUFLEN);
					if (recv(tcp_sockfd, buffer, BUFLEN, 0) <= 0) {
						close_all(&read_fds, fdmax, udp_sockfd, log);
						return 0;
					} 	
				}
			}
		}
	}	
	close_all(&read_fds, fdmax, udp_sockfd, log);
	return 0;
}	
