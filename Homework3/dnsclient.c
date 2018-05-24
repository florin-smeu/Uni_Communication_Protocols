/* Copyright 2018 Florin-Ion Smeu (florin.ion.smeu@gmail.com) */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>

#pragma pack(1)

/* -- Arbitrary constants used throughout the program */
#define MAX_SERVERS 20 /* Maximum number of dns servers questioned */
#define IP_ADDR_LEN 16 /* Length in octets of an IP address (string) */ 
#define COMMENT_STR "#" /* The comment string used in dns_servers.log */
#define DELIM "." /* The delimiter between address labels */
#define TIMEOUT 5 /* Seconds the program waits for a DNS server to respond */
#define N_ARGS 3 /* Number of program arguments */ 
#define DNS_LOG_FILE "dns.log"
#define MSG_LOG_FILE "message.log"
#define DNS_SERV_FILE "dns_servers.conf"

/* -- Sizes of the structures utilized -- */ 
#define H_LEN sizeof(dns_header_t)
#define Q_LEN sizeof(dns_question_t)
#define RR_LEN sizeof(dns_rr_t)

/* -- Different size limits used in the DNS protocol and other constants -- */
#define UDP_LEN 512 /* Maximum octets of an UDP message */
#define NAME_LEN 255 /* Maximum octets of a domain name */
#define LABEL_LEN 63 /* Maximum octets of a label */ 
#define MAX_LABELS 10 /* Maximum number of labels in the qname section */
#define IP_LEN 4 /* IPv4 address length in octets */
#define DNS_PORT 53 /* Default port of the UDP connection */
#define IN 1 /* Class value for the Internet */

/* -- Query & Resource Record Type: -- */
#define A 1 /* IPv4 address */
#define NS 2 /* Authoritative name server */
#define CNAME 5 /* Canonical name for an alias */
#define SOA 6 /* Start Of a zone of Authority */
#define PTR 12 /* Domain name pointer (reverse look-up) */
#define MX 15 /* Mail exchange */
#define TXT 16 /* Text strings */

/* -- Define DNS message format -- */
/* Header section format */
/**                                 1  1  1  1  1  1
      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      ID                       |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    QDCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    ANCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    NSCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    ARCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
*/
typedef struct {
	unsigned short id; /* identification number */

	unsigned char rd :1; /* recursion desired */
	unsigned char tc :1; /* truncated message */
	unsigned char aa :1; /* authoritive answer */
	unsigned char opcode :4; /* purpose of message*/
	unsigned char qr :1; /* query/response flag: 0=query; 1=response */

	unsigned char rcode :4;
	unsigned char z :3;
	unsigned char ra :1;

	unsigned short qdcount;

	unsigned short ancount;
	unsigned short nscount;
	unsigned short arcount;
} dns_header_t;

/* Question section format */
/**                                 1  1  1  1  1  1
      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                                               |
    /                     QNAME                     /
    /                                               /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     QTYPE                     |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     QCLASS                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
*/

typedef struct {
	unsigned short qtype;
	unsigned short qclass;
} dns_question_t;

/* Resource record format */
/**                                 1  1  1  1  1  1
      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                                               |
    /                                               /
    /                      NAME                     /
    |                                               |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      TYPE                     |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     CLASS                     |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      TTL                      |
    |                                               |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                   RDLENGTH                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
    /                     RDATA                     /
    /                                               /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
*/

typedef struct {
	unsigned short type;
	unsigned short class;
	unsigned int ttl;
	unsigned short rdlength;
} dns_rr_t;

void error(char *msg)
{
	perror(msg);
	exit(0);
}

/* 
 * Function called when appropriate arguments are not given.
 */ 
void usage(char *file)
{
	fprintf(stderr, "Usage: %s ip/domain_name type\n", file);
	exit(0);
}

/*
 * Function that retrieves the type of a dns query based on a string.
 */
unsigned short get_type(char *type) 
{
	if (!strcmp(type, "A")) return A;
	if (!strcmp(type, "NS")) return NS;
	if (!strcmp(type, "CNAME")) return CNAME;
	if (!strcmp(type, "MX")) return MX;
	if (!strcmp(type, "SOA")) return SOA;
	if (!strcmp(type, "TXT")) return TXT;
	if (!strcmp(type, "PTR")) return PTR;
	return 0;  
}


/* 
 * Function that retrieves the string corresponding to a type of a query
 * based on the actual type.
 */
char *get_char_type(unsigned short type) 
{
	if (type == A) return "A";
	if (type == NS) return "NS";
	if (type == CNAME) return "CNAME";
	if (type == MX) return "MX";
	if (type == SOA) return "SOA";
	if (type == TXT) return "TXT";
	if (type == PTR) return  "PTR";
	return "UNKNOWN";
}

/* 
 * Helper function that retrieves the string corresponding to a class of a 
 * query.
 */
char *get_char_class(unsigned short class) 
{
	if (class == IN) return "IN";
	return "UNKNOWN";
}

/* 
 * This function is used to retrieve the class, type, ttl and rdlength fields
 * found in a resource record.
 */
void retrieve_partial_rr(unsigned char *msg, unsigned short *type,
						 unsigned short *class, unsigned int *ttl,
						 unsigned short *rdlength) 
{
	int offset = 0;
	unsigned short aux_class, aux_type, aux_rdlength;
	unsigned int aux_ttl;
	memcpy(&aux_type, &msg[offset], sizeof(unsigned short));
	aux_type = ntohs(aux_type);	
	memcpy(type, &aux_type, sizeof(unsigned short));	
	offset += sizeof(unsigned short);  	
	
	memcpy(&aux_class, &msg[offset], sizeof(unsigned short));
	aux_class = ntohs(aux_class);
	memcpy(class, &aux_class, sizeof(unsigned short));
	offset += sizeof(unsigned short);
	
	memcpy(&aux_ttl, &msg[offset], sizeof(unsigned int));
	aux_ttl = ntohl(aux_ttl);
	memcpy(ttl, &aux_ttl, sizeof(unsigned int));
	offset += sizeof(unsigned int);	
	
	memcpy(&aux_rdlength, &msg[offset], sizeof(unsigned short));
	aux_rdlength = ntohs(aux_rdlength);	
	memcpy(rdlength, &aux_rdlength, sizeof(unsigned short));
}

/* 
 * Function that retrieves a domain name starting at offset bytes from the 
 * beginning of message msg. It is a recursive function due to the fact that 
 * pointers may be used to represent the domain name.
 */ 
int retrieve_name(unsigned char *msg, int offset, unsigned char *name)
{
	unsigned char *name_ptr = &msg[offset];
	int name_idx = 0;
	while(name_ptr[name_idx] <= LABEL_LEN && name_ptr[name_idx] != 0) {
		strncat(name, &name_ptr[name_idx + 1], name_ptr[name_idx]);
		strcat(name, ".");
		name_idx += (name_ptr[name_idx] + 1);
	}
	
	unsigned short jump = 0;
	if (name_ptr[name_idx] > LABEL_LEN) {
		jump = name_ptr[name_idx];
		jump <<= 8;
		jump |= name_ptr[name_idx + 1];
		jump ^= 0xc000;
		name_idx += 2;
	}	
	
	if (jump > 0) retrieve_name(msg, jump, name);

	return name_idx;
}

/* 
 * Helper function that retrieves the rdata content from a RR of type A.
 */ 
void retrieve_a_rdata(unsigned char *msg, int offset, FILE *dns_log) 
{
	unsigned char rdata[IP_LEN];
	memcpy(&rdata, &msg[offset], IP_LEN);
	for (int i = 0; i < IP_LEN - 1; ++i) fprintf(dns_log, "%u.", rdata[i]);
	fprintf(dns_log, "%u\n", rdata[IP_LEN - 1]);
}

/* 
 * Helper function that retrieves the rdata content from a RR of type NS.
 */ 
void retrieve_ns_rdata(unsigned char *msg, int offset, FILE *dns_log)
{
	unsigned char rdata[NAME_LEN];
	memset(&rdata, 0, sizeof(rdata));
	retrieve_name(msg, offset, rdata);
	fprintf(dns_log, "%s\n", rdata);
	return;
}

/* 
 * Helper function that retrieves the rdata content from a RR of type CNAME.
 */ 
void retrieve_cname_rdata(unsigned char *msg, int offset, FILE *dns_log)
{
	unsigned char rdata[NAME_LEN];
	memset(&rdata, 0, sizeof(rdata));
	retrieve_name(msg, offset, rdata);
	fprintf(dns_log, "%s\n", rdata);
}

/* 
 * Helper function that retrieves the rdata content from a RR of type MX.
 */ 
void retrieve_mx_rdata(unsigned char *msg, int offset, FILE *dns_log)
{
	unsigned short preference;
	unsigned char exchange[NAME_LEN];
	memset(&exchange, 0, sizeof(exchange));
	memcpy(&preference, &msg[offset], sizeof(unsigned short));
	fprintf(dns_log, "%hu ", ntohs(preference));
	retrieve_name(msg, offset + sizeof(unsigned short), exchange);
	fprintf(dns_log, "%s\n", exchange);
}

/* 
 * Helper function that retrieves the rdata content from a RR of type SOA.
 */ 
void retrieve_soa_rdata(unsigned char *msg, int offset, FILE *dns_log)
{
	unsigned char mname[NAME_LEN];
	memset(&mname, 0, sizeof(mname));
	int rname_offset = retrieve_name(msg, offset, mname);
	offset += rname_offset;
	fprintf(dns_log, "%s ", mname);

	unsigned char rname[NAME_LEN];
	memset(&rname, 0, sizeof(rname));
	int serial_offset = retrieve_name(msg, offset, rname);
	offset += serial_offset;
	fprintf(dns_log, "%s ", rname);
	
	unsigned int serial;
	memcpy(&serial, &msg[offset], sizeof(unsigned int));
	offset += sizeof(unsigned int);
	serial = ntohl(serial);
	fprintf(dns_log, "%u ", serial);

	int refresh;
	memcpy(&refresh, &msg[offset], sizeof(int));
	offset += sizeof(int);
	refresh = htonl(refresh);
	fprintf(dns_log, "%d ", refresh);
	
	int retry;
	memcpy(&retry, &msg[offset], sizeof(int));
	offset += sizeof(int);
	retry = htonl(retry);
	fprintf(dns_log, "%d ", retry);
	
	int expire;
	memcpy(&expire, &msg[offset], sizeof(int));
	offset += sizeof(int);
	expire = htonl(expire);
	fprintf(dns_log, "%d ", expire);

	int minimum;
	memcpy(&minimum, &msg[offset], sizeof(int));
	offset += sizeof(int);
	minimum = htonl(minimum);
	fprintf(dns_log, "%d\n", minimum);
}

/* 
 * Helper function that retrieves the rdata content from a RR of type TXT.
 */ 
void retrieve_txt_rdata(unsigned char *msg, int offset, int rdlength, 
						FILE *dns_log)
{
	unsigned char rdata[NAME_LEN];
	memset(&rdata, 0, sizeof(rdata));
	memcpy(&rdata, &msg[offset], rdlength);
	fprintf(dns_log, "%s\n", rdata);
}

/* 
 * Helper function that retrieves the rdata content from a RR of type PTR.
 */ 
void retrieve_ptr_rdata(unsigned char *msg, int offset, int rdlength, 
					   FILE *dns_log) 
{
	unsigned char rdata[NAME_LEN];
	memset(&rdata, 0, sizeof(rdata));
	retrieve_name(msg, offset, rdata);
	fprintf(dns_log, "%s\n", rdata);  
}
	

/* 
 * Function that retrieves the header section from a received message.
 */
dns_header_t retrieve_header(unsigned char *msg) 
{
	dns_header_t h;
	int offset = 0;

	/* Process the id field */	
	unsigned short id;
	memcpy(&id, &msg[offset], sizeof(unsigned short));
	offset += sizeof(unsigned short);
	id = ntohs(id);
	h.id = id;
	
	/* Process the flags */
	unsigned short flags;
	memcpy(&flags, &msg[offset], sizeof(unsigned short));
	offset += sizeof(unsigned short);
	flags = ntohs(flags);
	memcpy(&h + sizeof(unsigned short), &flags, sizeof(unsigned short));

	/* Process the qdcount field */
	unsigned short qdcount;
	memcpy(&qdcount, &msg[offset], sizeof(unsigned short));
	offset += sizeof(unsigned short);
	qdcount = ntohs(qdcount);
	h.qdcount = qdcount;
	
	/* Process the ancount field */
	unsigned short ancount;
	memcpy(&ancount, &msg[offset], sizeof(unsigned short));
	offset += sizeof(unsigned short);
	ancount = ntohs(ancount);
	h.ancount = ancount;
	
	/* Process the nscount field */
	unsigned short nscount;
	memcpy(&nscount, &msg[offset], sizeof(unsigned short));
	offset += sizeof(unsigned short);
	nscount = ntohs(nscount);
	h.nscount = nscount;
	
	/* Process the arcount field */
	unsigned short arcount;
	memcpy(&arcount, &msg[offset], sizeof(unsigned short));
	offset += sizeof(unsigned short);
	arcount = ntohs(arcount);
	h.arcount = arcount;
	
	return h;
}

/* 
 * Function that retrieves a question section from a received message.
 */  
int retrieve_question(unsigned char *msg, int offset, FILE *dns_log)
{
	/* Process the qname field */	
	unsigned char qname[NAME_LEN];
	memset(&qname, 0, sizeof(qname));
	int name_idx = retrieve_name(msg, offset, qname);
	offset += (name_idx + 1);

	/* Process the qtype field */
	unsigned short qtype;
	memcpy(&qtype, &msg[offset], sizeof(unsigned short));
	qtype = ntohs(qtype);
	offset += sizeof(unsigned short);
	
	/* Process the qclass field */
	unsigned short qclass;
	memcpy(&qclass, &msg[offset], sizeof(unsigned short));
	qclass = ntohs(qclass);
	offset += sizeof(unsigned short);

	fprintf(dns_log, "%s %s %s\n", qname, get_char_class(qclass), 
			get_char_type(qtype)); 
		
	return offset;
}
				 
/* 
 * Function that retrieves a resource record from a received message. 
 */
int retrieve_rr(unsigned char *msg, int offset, FILE *dns_log) 
{
	unsigned char name[NAME_LEN];
	memset(&name, 0, sizeof(name));
	
	/*Process the name field */
	int name_idx = retrieve_name(msg, offset, name);

	/*Process the rest of the resorce record */
	unsigned short class, type, rdlength;
	unsigned int ttl;
	unsigned char *partial_ptr = &msg[offset + name_idx];
	
	retrieve_partial_rr(partial_ptr, &type, &class, &ttl, &rdlength);
	if (strcmp(get_char_type(type), "UNKNOWN") == 0) 
		fprintf(dns_log, "%s %s %s\n", name, get_char_class(class), 
				get_char_type(type));
	else fprintf(dns_log, "%s %s %s ", name, get_char_class(class), 
				 get_char_type(type));	

	/* Process the rdata field */
	int rdata_offset = offset + name_idx + RR_LEN;

	if (type == A) retrieve_a_rdata(msg, rdata_offset, dns_log);
	if (type == NS) retrieve_ns_rdata(msg, rdata_offset, dns_log);
	if (type == CNAME) retrieve_cname_rdata(msg, rdata_offset, dns_log);
	if (type == MX) retrieve_mx_rdata(msg, rdata_offset, dns_log);
	if (type == SOA) retrieve_soa_rdata(msg, rdata_offset, dns_log);
	if (type == TXT) retrieve_txt_rdata(msg, rdata_offset, rdlength, dns_log); 	
	if (type == PTR) retrieve_ptr_rdata(msg, rdata_offset, rdlength, dns_log);

	return rdata_offset + rdlength; 
}	

/* 
 * Function that create tokens from string str, based on the delimiter DELIM.
 * It also keeps track of the lengths of the tokens using the token_len vector.
 */	
int create_tokens(unsigned char *str, char **token, char *token_len)
{
	token[0] = strtok(str, DELIM);
	token_len[0] = strlen(token[0]);	
	int token_index = 0;
	while (token[token_index] != NULL && token_index < MAX_LABELS) {	
		token_index++;
		token[token_index] = strtok(NULL, DELIM);
		if (token[token_index] == NULL) break;
		token_len[token_index] = strlen(token[token_index]);
	}
	return token_index;
}

/* 
 * Helper function that creates the qname field of a question section of a DNS
 * query. Example: www.google.com needs to become 3www6google3com\0
 */ 
void create_qname(char *qname, char **token, char *token_len, int token_index,
				  int qtype) 
{
	/* Reverse look-up (invert the bytes of the IP address) */
	if (qtype == PTR) {
		int  i = 0, j = IP_LEN - 1;
		while (i < j) {
			char tmp[token_len[i]];
			memcpy(&tmp, &token[i], sizeof(tmp));
			memcpy(&token[i], &token[j], strlen(token[j]));
			memcpy(&token[j], &tmp, sizeof(tmp));
			
			char tmp_len = token_len[i];
			token_len[i] = token_len[j];
			token_len[j] = tmp_len;
			
			i++;
			j--;
		}
	}
	
	/* Ordinary DNS query */
	int pos = 0;
	for (int i = 0; i < token_index; i++) {
		qname[pos] = token_len[i];
		pos++;
		for (int j = 0; j < token_len[i]; ++j) {
			qname[pos] = token[i][j];
			pos++;
		}		
	}

	/* Reverse lookup (add "in-addr" and "arpa" strings to the cname field) */
	if (qtype == PTR) {	
		qname[pos] = 7;
		pos++;
		char aux1[8], aux2[5];
		strcpy(aux1, "in-addr");
		strcpy(aux2, "arpa");
		for (int i = 0; i < 7; ++i) {
			qname[pos] = aux1[i];
			pos++;
		}
		qname[pos] = 4;
		pos++;
		for (int i = 0; i < 5; ++i) {
			qname[pos] = aux2[i];
			pos++;
		}
	}	

	qname[pos] = 0;
}

int main(int argc, char *argv[]) 
{
	clock_t start = clock();
	
	if (argc != N_ARGS) usage(argv[0]);

	/* Open the log files and the dns servers' file */	
	FILE *dns_log = fopen(DNS_LOG_FILE, "a"); 
	FILE *msg_log = fopen(MSG_LOG_FILE, "a");
	FILE *dns_serv_file = fopen(DNS_SERV_FILE, "rt");
	if (dns_log == NULL || msg_log == NULL || dns_serv_file == NULL) 
		error("ERROR opening I/O files");	

	/* Read and store information about the dns servers questioned */
	char **dns_serv_ip = (char **) malloc(MAX_SERVERS * sizeof(char *));
    for (int i = 0; i < MAX_SERVERS; ++i) 
		dns_serv_ip[i] = (char *) malloc(IP_ADDR_LEN * sizeof(char));
	int last_ip_index = 0, crt_ip_index = 0;	
	char *line = NULL;
	size_t len = 0;
	while (getline(&line, &len, dns_serv_file) != -1) {
		if (strncmp(line, COMMENT_STR, strlen(COMMENT_STR)) != 0 &&
			strlen(line) > 1) {
			strncpy(dns_serv_ip[last_ip_index], line, strlen(line) - 1);	 
			last_ip_index++;
		}
	}	
	fclose(dns_serv_file);

	/* Open UDP connection */
	int udp_sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (udp_sockfd < 0) error("ERROR opening UDP socket");
	
	/* Set timeout interval for udp_sockfd */
	struct timeval tv;
	tv.tv_sec = TIMEOUT;
	tv.tv_usec = 0;
	if (setsockopt(udp_sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
		close(udp_sockfd);
		error("ERROR setting timeout to socket");
	}
	
	/* Flag used to determine whether a DNS server has responded to a query */
	int success = 0;
	
	int send_len = 0;
	unsigned char send_buf[UDP_LEN], recv_buf[UDP_LEN];
	dns_header_t r_header;
	int recv = 0;

	while (!success && crt_ip_index < last_ip_index) {
		/* Information of the queried dns server */
		struct sockaddr_in dns_serv_addr;
		memset (&dns_serv_addr, 0, sizeof(dns_serv_addr));
		dns_serv_addr.sin_family = AF_INET;
		dns_serv_addr.sin_port = htons(DNS_PORT);
		inet_aton(dns_serv_ip[crt_ip_index], &dns_serv_addr.sin_addr);

		/* Set DNS header structure */
		dns_header_t send_header;
		memset(&send_header, 0, H_LEN);
		send_header.id = (unsigned short) htons(getpid());	
		send_header.rd = 1;
		send_header.qdcount = htons(1);
		

		/*Set DNS question structure */

		/* Construct the qname field as required in the RFC 1035 */
		int qtype = get_type(argv[2]);
		if (!qtype) {
			close(udp_sockfd);
			error("ERROR query type undefined");
		}
		unsigned char *aux_argv1 = malloc((strlen(argv[1]) + 1) * 
									  	  sizeof(unsigned char));
		strcpy(aux_argv1, argv[1]);

		char qname[MAX_LABELS * LABEL_LEN + 1];
		memset(&qname, 0, sizeof(qname));	
		unsigned char *token[LABEL_LEN]; 
		unsigned char token_len[LABEL_LEN];		
		int token_index = create_tokens(aux_argv1, (char **) token, token_len);
		create_qname((char *) qname, (char **) token, token_len, token_index, 
				 	 qtype); 	
	
		dns_question_t question;
		question.qtype = htons(qtype);
		question.qclass = htons(IN);

		/* Create payload to be sent to the DNS server */
		memset(&send_buf, 0, UDP_LEN);
		int qname_len = (int) strlen((const char *) qname) + 1;
		memcpy(&send_buf, &send_header, H_LEN);
		memcpy(&(send_buf[H_LEN]), &qname, qname_len);
		memcpy(&(send_buf[H_LEN + qname_len]), &question, Q_LEN);  		
		send_len = H_LEN + qname_len + Q_LEN;

		/* Variables used in the recvfrom call */
		memset(&recv_buf, 0, UDP_LEN);
		struct sockaddr_in from_dns_serv;
		unsigned int addr_len = sizeof(struct sockaddr);	

		/* Send message to DNS server via UDP connection */
		int sent = sendto(udp_sockfd, send_buf, send_len, 0, 
				   		  (struct sockaddr *) &dns_serv_addr, 
			   	   		  sizeof(struct sockaddr));
		if (sent <= 0) {
			close(udp_sockfd);
			error("ERROR sending UDP message");
		}  	

		/* Receive answer from the DNS server */
		recv = recvfrom(udp_sockfd, recv_buf, UDP_LEN, 0, 
				 		(struct sockaddr *) &from_dns_serv, &addr_len);
		if (recv <= 0) {
			printf("DNS server %s did not respond\n", 
				   dns_serv_ip[crt_ip_index]);
			if (crt_ip_index < last_ip_index) 
				printf("Trying DNS server %s\n", 
					   dns_serv_ip[crt_ip_index + 1]); 
			crt_ip_index++;
			continue;	
		}

		/* Retrieve the header of the message sent back by the DNS server. */
		r_header = retrieve_header(recv_buf);
	
		/* Count the different types of answers received from the DNS server */
		if (r_header.ancount == 0 && 
			r_header.nscount == 0 &&
			r_header.arcount == 0) {		
			printf("DNS server %s provided no answer\n", 
				   dns_serv_ip[crt_ip_index]);
			if (crt_ip_index < last_ip_index) 
				printf("Trying DNS server %s\n", 
					   dns_serv_ip[crt_ip_index + 1]);
			crt_ip_index++;
			continue;
		}
	
		/* The DNS server has successfully responded to the query */
		success = 1;	 
	}

	/* Print sent message into the message log file */	
	for (int i = 0; i < send_len; ++i) fprintf(msg_log, "%X ", send_buf[i]);	
	fprintf(msg_log, "\n");
	fflush(msg_log);
	fclose(msg_log);

	/* Print DNS server and query information in the dns log file */
	fprintf(dns_log, "Trying \"%s\" [%s]\n", argv[1], argv[2]);

	/* Print information about the header in the dns log file */
	fprintf(dns_log, ";; ->>HEADER<<- id: %hu\n", r_header.id); 
	fprintf(dns_log, ";; QUERY: %hu, ANSWER: %hu, ", r_header.qdcount, 
			r_header.ancount);
	fprintf(dns_log , "AUTHORITY %hu, ADDITIONAL: %hu\n", r_header.nscount, 
			r_header.arcount);
	
	/* Retrieve the question section of the received message */
	if (r_header.qdcount > 0) fprintf(dns_log, "\n;; QUESTION SECTION:\n");
	int offset = retrieve_question(recv_buf, H_LEN, dns_log);

	/* Read the answer section */
	if (r_header.ancount > 0) fprintf(dns_log, "\n;; ANSWER SECTION:\n");
	for (int i = 0; i < r_header.ancount; ++i) {
		offset = retrieve_rr(recv_buf, offset, dns_log);
	}
		
	/*Read the authority section */
	if (r_header.nscount > 0) fprintf(dns_log, "\n;; AUTHORITY SECTION:\n");
	for (int i = 0; i < r_header.nscount; ++i) {
		offset = retrieve_rr(recv_buf, offset, dns_log);
	}

	/*Read the additional section */
	if (r_header.arcount > 0) fprintf(dns_log, "\n;; ADDITIONAL SECTION:\n");
	for (int i = 0; i < r_header.arcount; ++i) {
		offset = retrieve_rr(recv_buf, offset, dns_log);
	}
	
	/* Print other relevant data about the transmission in the dns log file */ 
	double time_used;		
	clock_t end = clock();
	time_used = ((double) (end - start)) / CLOCKS_PER_SEC;	
	fprintf(dns_log, "\nReceived %d bytes from %s#%d in %.3lf ms\n\n", recv, 
			dns_serv_ip[crt_ip_index], DNS_PORT, time_used * 1e3);
	fclose(dns_log);

	return 0;
}
