#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "lib.h"
#include "klib.h"

#define HOST "127.0.0.1"
#define PORT 10000

/*
 * Function that creates the inital 'S' package
 */
unsigned char* create_s(int seq)
{       
	unsigned char* buffer = malloc(S_LEN * sizeof(unsigned char));
	s_pkg s;

        s.h.soh = SOH;
        s.h.len = S_LEN - 2;
        s.h.seq = seq;
        s.h.type = TYPE_S;

        s.d.maxl = MAXL;
        s.d.time = TIME;
        s.d.npad = NPAD;
        s.d.padc = PADC;
        s.d.eol = EOL;
        s.d.qctl = QCTL;
        s.d.qbin = QBIN;
        s.d.chkt = CHKT;
        s.d.rept = REPT;
        s.d.capa = CAPA;
        s.d.r = R;

        int crc_len = S_LEN - T_LEN;
        unsigned char crc_data[crc_len];
        memcpy(crc_data, &s, crc_len);

        s.t.check = crc16_ccitt(crc_data, crc_len);
        s.t.mark = MARK;
        memcpy(buffer, &s, S_LEN);

        return buffer;
}

/*
 * Function that creates a file header 'F' package
 */
unsigned char* create_f(char *filename, int seq)
{
        int header_len = H_LEN + strlen(filename) + T_LEN;
        unsigned char *buffer = malloc(header_len * sizeof(unsigned char));

        header h;
        h.soh = SOH;
        h.len = header_len - 2;;
        h.seq = seq;
        h.type = TYPE_F;

        memcpy(buffer, &h, H_LEN);
        memcpy(buffer + H_LEN, filename, strlen(filename));

        int crc_len = header_len - T_LEN;
        unsigned char crc_data[crc_len];
        memcpy(crc_data, buffer, (H_LEN + strlen(filename)));

        trailer t;
        t.check = crc16_ccitt(crc_data, crc_len);
        t.mark = MARK;

        memcpy(buffer + (header_len - T_LEN), &t, T_LEN);

        return buffer;
}

/* 
 * Function that creates a data 'D' package 
 */	
unsigned char* create_d(unsigned char* data_buffer, int nbytes, int seq)
{
        header h;
        h.soh = SOH;
        h.seq = seq;
        h.len = nbytes + H_LEN + T_LEN - 2;
        h.type = TYPE_D;

        int crc_len = nbytes + H_LEN;
        char crc_data[crc_len];
        memcpy(crc_data, &h, H_LEN);
        memcpy(crc_data + H_LEN, data_buffer, nbytes);

        trailer t;
        t.check = crc16_ccitt(crc_data, crc_len);
        t.mark = MARK;

        unsigned char* buffer = malloc((H_LEN + nbytes + T_LEN) *
				       sizeof(char));
        memcpy(buffer, &h, H_LEN);
        memcpy(buffer + H_LEN, data_buffer, nbytes);
        memcpy(buffer + H_LEN + nbytes, &t, T_LEN);

        return buffer;
}

/*
 * Function that creates an EOF 'Z' package, or an EOT 'B' package
 */
unsigned char* create_eo(int seq, char type)
{
        unsigned char *buffer = malloc(P_LEN * sizeof(unsigned char*));

        pkg e;
        e.h.soh = SOH;
        e.h.seq = seq;
        e.h.len = P_LEN - 2;
        e.h.type = type;

        int crc_len = H_LEN;
        char crc_data[crc_len];
        memcpy(crc_data, &e, H_LEN);

        e.t.check = crc16_ccitt(crc_data, crc_len);
        e.t.mark = MARK;

        memcpy(buffer, &e, P_LEN);
        return buffer;
}

/*
 * Utility function that sends a message to the receiver and checks if timeout 
 * takes place
 */
msg* check_timeout(msg* s, int seq)
{
        int ctr = 3;
        while (ctr > 0) {
                send_message(s);
                msg* r = receive_message_timeout(TIME * 1000);
                if (r == NULL) {
			printf("[timeout] seq = %d, try = %d\n", seq, 4 - ctr); 
                        ctr--;
		}
                else
                        return r;

        }
        return NULL;
}

/*
 * Function that sends a message to the receiver
 * It is ensured that the sender receives first an acknoledgement from 
 * the receiver, and that no timeout takes place
 */ 
msg* send(msg* s, int seq)
{
        msg *r = check_timeout(s, seq);
        if (r == NULL) 
                return NULL;

        while (r->payload[3] != TYPE_Y) {
		r = check_timeout(s, seq);
                if (r == NULL)         
			return NULL;
			
        }
        return r;
}

/* 
 * Increment the sequence number modulo mod 
 */
int increment_seq(int seq, int mod) 
{	
	return (seq + 1) % mod;
}

int main(int argc, char** argv) 
{
    	init(HOST, PORT);
		
	msg s;
	int seq = 0; 
	printf("\n      ##### BEGINNING TRANSMISSION. #####\n");	
		
	//send init package
	unsigned char* buffer = create_s(seq);		
	memcpy(&s.payload, buffer, S_LEN);
	s.len = S_LEN;
    	msg *r = send(&s, seq);
	if (r == NULL) {
		printf("=== Unable to establish connection ===\n\n");           
                printf("  ##### ABORTING TRANSMISSION. #####\n");   
		return 0;
	}
	seq = increment_seq(seq, MODULO_SEQ);
	
	for (int i = 1; i < argc; ++i) {
		printf("\n      ##### SENDING FILE: %s #####\n", argv[i]); 
		
		//open file for reading
		int fd = open(argv[i], O_RDONLY);	
		if (fd < 0) {
			 printf("=== File %s could not be"
				" opened ===\n\n", argv[i]);
                         printf(" ##### ABORTING TRASMISSION. #####\n");
                         return 0;
		}
		
		//send file header
		unsigned char* buffer = create_f(argv[i], seq); 	
		memcpy(&s.payload, buffer, strlen((char *) buffer));
		s.len = strlen((char *) buffer);
		r = send(&s, seq);
		if (r == NULL) {
			printf("=== Transmission experienced timeout ===\n\n");
			printf("   ##### ABORTING TRANSMISSION. #####\n");
			return 0;	
		}		
		seq = increment_seq(seq, MODULO_SEQ);
		
		//send data
		unsigned char* data_buffer = malloc(MAXL * 
						    sizeof(unsigned char));
		int nbytes = read(fd, data_buffer, MAXL);	
		
		while (nbytes == MAXL) {
			int len = H_LEN + nbytes + T_LEN;
			unsigned char* data = create_d(data_buffer, nbytes,
						       seq);		
			memcpy(&s.payload, data, len);
			s.len = len;
			r = send(&s, seq);
			if (r == NULL) {
				printf("=== Transmission experienced"
				       " timeout ===\n\n");
				printf("   ##### ABORTING TRANSMISSION." 
				       " #####\n");
				return 0;
			}
			seq = increment_seq(seq, MODULO_SEQ);

			nbytes = read(fd, data_buffer, MAXL);
		}
		
		int len =  H_LEN + nbytes + T_LEN;
		unsigned char* data = create_d(data_buffer, nbytes, seq);
		memcpy(&s.payload, data, len);
		s.len = len;
		send(&s, seq); 
		if (r == NULL) {
			printf("=== Transmission experienced timeout ===\n\n");
			printf("   ##### ABORTING TRANSMISSION. #####\n");
			return 0;
		}	
		seq = increment_seq(seq, MODULO_SEQ);

		//send eof
		unsigned char* eof_buffer = create_eo(seq, TYPE_Z);
		memcpy(&s.payload, eof_buffer, P_LEN);
		s.len = P_LEN;
		r = send(&s, seq);
		if (r == NULL) {
			printf("=== Transmission experienced timeout ===\n\n");
			printf("   ##### ABORTING TRANSMISSION. #####\n"); 
			return 0;
		}
		seq = increment_seq(seq, MODULO_SEQ);
			
		close(fd);
	}

	//send eot
	unsigned char* eot_buffer = create_eo(seq, TYPE_B);
	memcpy(&s.payload, eot_buffer, P_LEN);
	s.len = P_LEN;
	r = send(&s, seq);
    	return 0;
}
