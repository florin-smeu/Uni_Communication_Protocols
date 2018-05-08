#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <assert.h>

#define BUFLEN 256
#define N_ARGS 3
#define MAX_CLIENTS 100
#define NAME_LEN 12
#define PASSWD_LEN 8

/*
 * Structura care asigura memorarea informatiilor despre clientii conectati 
 * la server.
 * 
 * faileg_logins = numar de incercari esuate de login pentru un card
 * card = card pentru care sunt monitorizate incercarile esuate de login
 * transfer = 1 => clientul trebuie sa confirme transferul introducand 'y'/'n'
 * transfer_card = card catre care se va face transferul de bani
 * sum = suma de bani transferata
 */		
typedef struct {
	int failed_logins;
	int card;
	int transfer;
	int transfer_card;
	double sum;	
} Client;

/*
 * Structura care asigura memorarea informatiilor despre un cont
 *
 * logged = 0/1 => cont nelogat/logat
 * locked = 0/1 => cont neblocat/blocat
 */
typedef struct {
	char lastname[NAME_LEN];
	char firstname[NAME_LEN];
	int card;
	int pin;
	char passwd[PASSWD_LEN];
	double balance;
	int logged;
	int locked;
} Account;

void error(char *msg)
{
    perror(msg);
    exit(0);
}

void usage(char*file)
{
    fprintf(stderr,"Usage: %s port_server file\n",file);
    exit(0);
}

/*
 * Functia realizeaza citirea conturilor din baza de date si returneaza un
 * pointer catre o zona de memorie in care vor fi memorate aceste informatii. 
 */	
Account *read_accounts(FILE *database, int n_accts)
{
	Account *accts = (Account*) malloc(n_accts * sizeof(Account));
	for (int i = 0; i < n_accts; ++i) {
		fscanf(database, "%s", accts[i].lastname);
		fscanf(database, "%s", accts[i].firstname);
		fscanf(database, "%d", &accts[i].card);
		fscanf(database, "%d", &accts[i].pin);
		fscanf(database, "%s", accts[i].passwd);
		fscanf(database, "%lf", &accts[i].balance);
		accts[i].logged = 0;
		accts[i].locked = 0;
	}
	return accts;
}

/*
 * Functie helper care realizeaza printarea informatiilor despre conturile 
 * din baza de date.
 */
void print_accounts(Account *accts, int n_accts) 
{
	printf("%d\n", n_accts);
	for(int i = 0; i < n_accts; ++i) {
		printf("%s ", accts[i].lastname);
		printf("%s ", accts[i].firstname);
		printf("%d ", accts[i].card);
		printf("%d ", accts[i].pin);
		printf("%s ", accts[i].passwd);
		printf("%.2f ", accts[i].balance);
		printf("\n");
	}
}

/*
 * Functie care realizeaza actiunile necesare inchiderii unui client.
 */	
void close_client(Client *clients, int socket, fd_set *read_fds) 
{
		clients[socket].transfer = 0;
		clients[socket].card = 0;
		clients[socket].sum = 0;
		clients[socket].transfer_card = 0;
		clients[socket].failed_logins = 0; 
		close(socket);
		FD_CLR(socket, read_fds);
}

/* 
 * Functie care verifica posibilitatea realizarii login-ului pentru parametrii
 * primiti. Intoarce un int (0 = succes, restul = esec).
 */ 
int login(Account *accts, int n_accts, char *card, char *pin, int socket, 
		  Client *clients, char *full_name) 
{
	for (int i = 0; i < n_accts; ++i) {
		if (accts[i].card == atoi(card)) {
			if ((clients[socket].failed_logins == 2 &&
				 accts[i].pin != atoi(pin)) || 
				accts[i].locked == 1) {
				accts[i].locked = 1;
				clients[socket].failed_logins = 3;
				return -5;
			}
			if (accts[i].pin != atoi(pin)) {
				clients[socket].failed_logins++;
				return -3;
			}
			if (accts[i].logged == 1) return -2;
			accts[i].logged = 1;
			clients[socket].failed_logins = 0;
			strcpy(full_name, accts[i].lastname);	
			strcat(full_name, " ");
			strcat(full_name, accts[i].firstname);
			return 0;
		}
	}
	return -4;
}			

/*
 * Functie helper care, in functie de flagul primit, completeaza bufferul 
 * ce urmeaza sa fie trimis la client.
 */ 
void login_msg(char *buffer, char* full_name, int flag) 
{
	switch (flag) {
		case -5:
			strcpy(buffer, "IBANK> -5 : Card blocat");
			break;
		case -2:
			strcpy(buffer, "IBANK> -2 : Sesiune deja deschisa");		
			break;
		case 0:		
			strcpy(buffer, "IBANK> Welcome ");
			strcat(buffer, full_name);
			break;
		case -3: 
			strcpy(buffer, "IBANK> -3 : Pin gresit");		
			break;			
		case -4:
			strcpy(buffer, "IBANK> -4 : Numar card inexistent");
	}	
}

/* 
 * Logout verifica posibilitatea delogarii unui client. 
 */
void logout(Account *accts, int n_accts, int socket, Client *clients, 
			char* buffer) 
{
	for (int i = 0; i < n_accts; ++i)
		if (accts[i].card == clients[socket].card) {
			accts[i].logged = 0;
			clients[socket].card = 0;
			clients[socket].failed_logins = 0;
		}
	strcpy(buffer, "IBANK> Clientul a fost deconectat");

}

/* 
 * Functia listsold populeaza buffer-ul cu sold-ul curent al clientului care 
 * a facut solicitarea.
 */ 
void listsold(Account *accts, int n_accts, int socket, Client *clients,
			  char * buffer) 
{	
	for (int i = 0; i < n_accts; ++i) 
		if (accts[i].card == clients[socket].card)
			sprintf(buffer, "IBANK>  %.2lf", accts[i].balance);	
}
/*
 * Functia verifica posibilitatea realizarii transferului de bani de la un 
 * cont la altul (0 = succes, restul = esec).
 */
int transfer(Account *accts, int n_accts, char *card, double sum, 
			 char *full_name) 
{
	for (int i = 0; i < n_accts; ++i) 
		if (accts[i].card == atoi(card)) {
			if (accts[i].balance < sum) return -8;
			sprintf(full_name, "%s %s", accts[i].lastname, accts[i].firstname);
			return 0;
		}	
	return -4;
}

/* 
 * Helper care populeaza buffer-ul cu mesajul de transfer de trimis la client.
 */
void transfer_msg(char *buffer, char *full_name, double sum, int flag) 
{
	switch (flag) {
		case -8:
			strcpy(buffer, "IBANK> -8 : Fonduri insuficiente");
			break;
		case 0:
			sprintf(buffer, "IBANK> Transfer %.2lf catre %s? [y/n]", sum, 
					full_name); 
			break;
		case -4:		
			strcpy(buffer, "IBANK> -4 : Numar card inexistent");
	}	
}

/* 
 * Functie care realizeaza propriu-zis transferul, daca clientul introduce
 * caracterul 'y'. 
 */
void process_transfer(Account *accts, int n_accts, int socket, Client *clients,
					  char *buffer) 
{	
	if (buffer[0] == 'y') {
		for (int i = 0; i < n_accts; ++i) {
			if (accts[i].card == clients[socket].card)
				accts[i].balance -= clients[socket].sum;
			if (accts[i].card == clients[socket].transfer_card)	
				accts[i].balance += clients[socket].sum;
		}
		clients[socket].transfer_card = 0;
		clients[socket].sum = 0;	
		clients[socket].transfer = 0;
		strcpy(buffer, "IBANK> Transfer realizat cu succes");
	} else 
		strcpy(buffer, "IBANK> -9 : Operatie anulata");		
} 

/* 
 * Verifica posibilitatea deblocarii contului primit ca parametru.
 */
int unlock(Account *accts, int n_accts, char *card) 
{
	int card_num = atoi(card);
	for (int i = 0; i < n_accts; ++i) {
		if (accts[i].card == card_num && accts[i].locked == 1) return 0;
		if (accts[i].card == card_num) return -6;
	} 
	return -4;
}

/* 
 * Helper prin care se copiaza in buffer primul mesaj de trimis la client
 * in cazul deblocarii.
 */
void unlock_msg1(char *buffer, int flag) 
{
	switch (flag) {
		case -4: 
			strcpy(buffer, "UNLOCK> -4 : Numar card inexistent");
			break;	
		case -6:
			strcpy(buffer, "UNLOCK> -6 : Operatie esuata");
			break;
		case 0: 
			strcpy(buffer, "UNLOCK> Trimite parola secreta");
	}
}

/*  
 * Helper prin care se copiaza in buffer al doilea mesaj de trimis la client
 * in cazul deblocarii.
 */
void unlock_msg2(char *buffer, int flag) 
{
	if (flag == 0) strcpy(buffer, "UNLOCK> Client deblocat");
	else strcpy(buffer, "UNLOCK> -7 : Deblocare esuata");
}

/* 
 * Functie care verifica daca parola introdusa de client pentru fi deblocat 
 * contul este corecta (0 = succes, -1 = esec). 
 */ 
int verify_passwd(Account *accts, int n_accts, char *card, char *passwd,
				  int socket, Client *clients) 
{
	int card_num = atoi(card);
	char *tk1 = strtok(passwd, "\n");
	for (int i = 0; i < n_accts; ++i) {
		printf("%d %d %s %s\n", accts[i].card, card_num, accts[i].passwd, tk1);
		if (accts[i].card == card_num &&
			strncmp(accts[i].passwd, tk1, PASSWD_LEN) == 0) {
			accts[i].locked = 0;
			clients[socket].failed_logins = 0;
			return 0;
		}
	}
	return -1;
}
			
int main(int argc, char *argv[])
{
	if (argc != N_ARGS) usage(argv[0]);
	
	// Citire date despre conturi din baza de date
	FILE *database = fopen(argv[2], "rt");
	int n_accts;	
	fscanf(database, "%d", &n_accts);
	Account *accts = read_accounts(database, n_accts);	
	print_accounts(accts, n_accts);

	// Deschidere socket TCP principal si socket UDP
	int tcp_sockfd, udp_sockfd;
	tcp_sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (tcp_sockfd < 0) error("Eroare deschidere socket TCP");
	udp_sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (udp_sockfd < 0) error("Eroare deschidere socket UDP");
	
	// Completare informatii adresa server
	struct sockaddr_in serv_addr;
	memset (&serv_addr, 0, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(atoi(argv[1]));
	serv_addr.sin_addr.s_addr = INADDR_ANY;	

	// Bind socket TCP principal si socket UDP
	int yes = 1;
	if(setsockopt(tcp_sockfd, SOL_SOCKET,
				  SO_REUSEADDR, &yes, sizeof(int)) == -1) {
		error("EROARE refolosire socket");
	}	
	if (bind(tcp_sockfd, (struct sockaddr *) &serv_addr, 
			 sizeof(struct sockaddr)) < 0) error("EROARE binding TCP server");
	if (bind(udp_sockfd, (struct sockaddr *) &serv_addr, 
			 sizeof(struct sockaddr)) < 0) error("EROARE binding UDP server");
	
	// Listen socket TCP principal
	if (listen(tcp_sockfd, MAX_CLIENTS) < 0) error("Eroare listen server"); 
	
	fd_set read_fds, tmp_fds;
	int fdmax = tcp_sockfd;
	FD_ZERO(&read_fds);
	FD_ZERO(&tmp_fds);
	FD_SET(tcp_sockfd, &read_fds);
	FD_SET(STDIN_FILENO, &read_fds);
	FD_SET(udp_sockfd, &read_fds);
		
	int new_sockfd;
	struct sockaddr_in tcp_addr;
	unsigned int tcp_addr_len = (unsigned int) sizeof(struct sockaddr);
	
	// Retinem informatii despre clientii conectati 
	char buffer[BUFLEN];
	Client clients[MAX_CLIENTS]; 	
	memset(clients, 0, MAX_CLIENTS * sizeof(Client));

	while(1) {
		tmp_fds = read_fds;
		
		// Multiplexare	
		if (select(fdmax + 1, &tmp_fds, NULL, NULL, NULL) < 0)
			error("EROARE select server");
		
		for (int i = 0; i <= fdmax; ++i) {
			if (FD_ISSET(i, &tmp_fds)) {
				if (i == tcp_sockfd) {
					// Un nou client doreste sa se conecteze la server
					new_sockfd = accept(tcp_sockfd, 
										(struct sockaddr *) &tcp_addr,
										&tcp_addr_len);
					if (new_sockfd < 0) error("EROARE accept server");
					else { 
						FD_SET(new_sockfd, &read_fds);
						printf("Client conectat pe socket %d\n", new_sockfd);
						if (new_sockfd > fdmax) fdmax = new_sockfd;	
					}
				} else if (i == STDIN_FILENO) {
					// Serverul primeste comenzi de la tastatura
					memset(buffer, 0, BUFLEN);
					fgets(buffer, BUFLEN - 1, stdin);
					// Inchidere server	si notificare clienti
					if (strncmp(buffer, "quit", 4) == 0) {
						for (int j = 0; j <= fdmax; ++j) {
								close(j);
								FD_CLR(j, &read_fds);
						}	
						close(tcp_sockfd);
						close(udp_sockfd);
						return 0;
					}
				} else if (i == udp_sockfd) {
					// Serverul primeste comenzi pe socketul UDP
					struct sockaddr_in udp_aux_addr;
					unsigned int udp_addr_len = sizeof(struct sockaddr);			
				
					memset(buffer, 0, BUFLEN);
					if (recvfrom(i, buffer, sizeof(buffer), 0, 
								 (struct sockaddr *) &udp_aux_addr,
								 &udp_addr_len) == -1) {
						close(i);
						FD_CLR(i, &read_fds);
						continue;
					}
	
					char aux_buffer[BUFLEN];
					strcpy(aux_buffer, buffer);
					char *tk1 = strtok(buffer, " "); 
					
					// Clientul doreste sa deblocheze contul
					if (strcmp(tk1, "unlock") == 0) {
						char *tk2 = strtok(NULL, " ");
						char aux_tk2[6];
						strncpy(aux_tk2, tk2, 6);
						int u = unlock(accts, n_accts, aux_tk2);

						strcpy(buffer, aux_buffer);
						unlock_msg1(buffer, u);
						if (sendto(i, buffer, strlen(buffer) + 1, 0, 
								   (struct sockaddr *) &udp_aux_addr,
								   udp_addr_len) == -1) {
							close(i);
							FD_CLR(i, &read_fds);
							continue;
						}
						// u = 0 => Se solicita introducerea parolei secrete
						if (u == 0) {
							if (recvfrom(i, buffer, sizeof(buffer), 0, 
									 	 (struct sockaddr *) &udp_aux_addr, 
									 	 &udp_addr_len) == -1) {
								close(i);
								FD_CLR(i, &read_fds);	
								continue;
							}
							// Se verifica parola
							int v = verify_passwd(accts, n_accts, aux_tk2,
												  buffer, i, clients);		
					 		unlock_msg2(buffer, v);
							if (sendto(i, buffer, strlen(buffer) + 1, 0,
									   (struct sockaddr *) &udp_aux_addr, 
									   udp_addr_len) == -1) {
								close(i);
								FD_CLR(i, &read_fds);
								continue;	
							}
						}
					}		
				} else {
					// Serverul primeste comezi de la unul din clientii TCP
					memset(buffer, 0, BUFLEN);
					if (recv(i, buffer, sizeof(buffer), 0) <= 0) {
						close(i);
						FD_CLR(i, &read_fds);
						continue;
					}
					
					char aux_buffer[BUFLEN];
					strcpy(aux_buffer, buffer);
					char* tk1 = strtok(buffer, " \n");
					
					// Clientul doreste	sa se logheze
					if (strcmp(tk1, "login") == 0) {
						char *tk2 = strtok(NULL, " \n");
						if (clients[i].card != atoi(tk2)) {
							clients[i].card = atoi(tk2);
							clients[i].failed_logins = 0;
						}
						char *tk3 = strtok(NULL, " \n");	
						char full_name[NAME_LEN * 2 + 1];
						int c = login(accts, n_accts, tk2, tk3, i, clients,
									  full_name);
						login_msg(buffer, full_name, c);		
					}
					
					// Clientul doreste delogarea
					if (strcmp(tk1, "logout") == 0) 
						logout(accts, n_accts, i, clients, buffer);
					
					// Interogare sold
					if (strcmp(tk1, "listsold") == 0)
						listsold(accts, n_accts, i, clients, buffer);
					
					// Clientul doreste sa transfere o suma de bani
					if (strcmp(tk1, "transfer") == 0) {
						char *tk2 = strtok(NULL, " \n");
						char aux_tk2[6];
						strncpy(aux_tk2, tk2, 6);
						char *tk3 = strtok(NULL, " \n");	
						double sum = 0;
						sscanf(tk3, "%lf", &sum);
						double aux_sum = sum;
						char full_name[2 * NAME_LEN + 1];
						int t = transfer(accts, n_accts, tk2, sum, full_name);
						transfer_msg(buffer, full_name, sum, t);
						if (t == 0) {	
							if (send(i, buffer, strlen(buffer) + 1, 0) <= 0) {
								close_client(clients, i, &read_fds);
								continue;
							}
							clients[i].transfer = 1;
							clients[i].transfer_card = atoi(aux_tk2);
							clients[i].sum = aux_sum;
							continue;	
						}
					}
	
					// A fost primit mesajul quit (inchidere client)
					if (strcmp(tk1, "quit") == 0) {
						close_client(clients, i, &read_fds);
						continue;	
					}
		
					// Clientul curent trebuie sa confirme sau sa infirme 
					// transferul.
					if (clients[i].transfer == 1) {
						strcpy(buffer, aux_buffer);
						process_transfer(accts, n_accts, i, clients, buffer);
					}					
					send(i, buffer, strlen(buffer) + 1, 0);
				}	
			}				
		}
	}
	close(tcp_sockfd);
	close(udp_sockfd);				
	return 0;
}
