#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include "lib.h"
#include "klib.h"

#define HOST "127.0.0.1"
#define PORT 10001


/* 
 * Function that creates the initial 'S' acknowledgement package, based on 
 * the received initial package	
 */ 
unsigned char* create_s_ack(msg* r, int seq)
{
	unsigned char* buffer = malloc(S_LEN * sizeof(unsigned char));
        s_pkg s;
	
        s.h.soh = r->payload[0];
        s.h.len = r->payload[1];
        s.h.seq = r->payload[2];
        s.h.type = r->payload[3];

        s.d.maxl = r->payload[4];
        s.d.time = r->payload[5];
        s.d.npad = r->payload[6];
        s.d.padc = r->payload[7];
        s.d.eol = r->payload[8];
        s.d.qctl = r->payload[9];
        s.d.qbin = r->payload[10];
        s.d.chkt = r->payload[11];
        s.d.rept = r->payload[12];
        s.d.capa = r->payload[13];
        s.d.r = r->payload[14];

        int crc_len = S_LEN - T_LEN;
        unsigned char crc_data[crc_len];
        memcpy(crc_data, &s, crc_len);

        s.t.check = crc16_ccitt(crc_data, crc_len);
        s.t.mark = MARK;
        memcpy(buffer, &s, S_LEN);
	
        return buffer;
}

/*
 * Check if timeout takes place during the transmission of the initial 
 * package
 */ 
msg* check_timeout_s()
{
        int ctr = 3;
        while (ctr > 0) {
                msg *r = receive_message_timeout(1000 * TIME);
                if (r == NULL)
                        ctr--;
                else
                        return r;
        }
        return NULL;
}

/*
 * Function that sends the acknowledgement of the initial package
 */
void send_ack_s(int seq, msg* r)
{
        msg *s = malloc(sizeof(msg));

        unsigned char* buffer = create_s_ack(r, seq);
        memcpy(s->payload, buffer, S_LEN);
        s->len = S_LEN;
	send_message(s);
}

/*
 * Function that sends the 'not acknowledged' package 
 */
void send_nak(int seq)
{
        msg* s = malloc(sizeof(msg));
        pkg n;  
        n.h.soh = SOH;
        n.h.len = P_LEN - 2;
        n.h.seq = seq;
        n.h.type = TYPE_N;

        unsigned char crc_data[H_LEN];
        memcpy(crc_data, &n, H_LEN);

        n.t.check = crc16_ccitt(crc_data, H_LEN);
        n.t.mark = MARK;

        memcpy(s->payload, &n, P_LEN);
	s->len = P_LEN;
	
        send_message(s);
}

/* 
 * Utility function that checks wether or not the messages have been corrupted
 * based on the Cyclic Redundancy Check
 */	
int check_crc(msg *r)
{
        int crc_len = r->len - T_LEN;
        unsigned char crc_data[crc_len];
        memcpy(crc_data, r->payload, crc_len);

        unsigned short crc = crc16_ccitt(crc_data, crc_len);

        unsigned short actual_crc = r->payload[r->len - 2];
        memcpy(&actual_crc, r->payload + (r->len - T_LEN), 2);

        if (actual_crc != crc) {
                printf("[incorrect crc] seq = %d\n", r->payload[2]);
		return -1;
        } else  {
                return 0;
        }
}

/* 
 * Function that ensures that the initial package has been correctly received
 */ 
msg* receive_s(int seq)
{
        msg *r = check_timeout_s();

        if (r == NULL)
                return NULL;

        while (check_crc(r) < 0) {
                send_nak(seq);
                r = check_timeout_s();
                if (r == NULL)
                        return NULL;
        }

        send_ack_s(seq, r);
	
        return r;
}

/* 
 * Function that sends the acknowledgement message to the sender 
 */
void send_ack(int seq)
{
        msg* s = malloc(sizeof(msg));

        pkg a;
        a.h.soh = SOH;
        a.h.len = P_LEN - 2;
        a.h.seq = seq;
        a.h.type = TYPE_Y;

        unsigned char crc_data[H_LEN];
        memcpy(crc_data, &a, H_LEN);

        a.t.check = crc16_ccitt(crc_data, H_LEN);
        a.t.mark = MARK;

        memcpy(s->payload, &a, P_LEN);
	s->len = P_LEN;
        send_message(s);
}

/* 
 * Utility function that ensures that a package is received properly
 */ 
msg* check_timeout()
{
	msg* r = receive_message_timeout(1000 * TIME);
	
	while (r == NULL) 
		r = receive_message_timeout(1000 * TIME);
	
	return r;
}	

/*
 * Function utilized to correcly receive a message from the sender
 * Acknoledgement messages are sent back accordingly
 */ 
msg* receive(int seq)
{
        msg *r = check_timeout();

        while (check_crc(r) < 0) {
        	send_nak(seq);
                r = check_timeout();
        }

        send_ack(seq);
        return r;
}

/*
 * Function that creates a file based on the information received in the 
 * file header 'F' package
 */
int create_file(msg* r, char *name)
{
        int filename_len = r->len - H_LEN - T_LEN;
        char *filename = malloc(filename_len * sizeof(char));
        memcpy(filename, r->payload + H_LEN, filename_len);

        char recv_filename[strlen(RECV_FILE_PREFIX) + filename_len];
        strcpy(recv_filename, RECV_FILE_PREFIX);
        strcat(recv_filename, filename);

        mode_t mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
	
	memcpy(name, recv_filename, strlen(RECV_FILE_PREFIX) + filename_len);
        return open(recv_filename, O_WRONLY | O_CREAT, mode);
}

/* 
 * Function that writes the content of a data 'D' package into the appropriate
 * file
 */
void write_data(msg* r, int fd)
{
        int data_len = r->len - H_LEN - T_LEN;

        char* data = malloc(data_len * sizeof(char));
        memcpy(data, r->payload + H_LEN, data_len);

        write(fd, data, data_len);
}

/* 
 * Increment sequence number modulo mod
 */ 
int increment_seq(int seq, int mod) 
{
	return (seq + 1) % mod;
}

int main(int argc, char** argv) 
{
    	init(HOST, PORT);
	
	int seq = 0;

	//receive init package
	msg* r = receive_s(seq);	
	if (r == NULL) {
		printf("=== Unable to establish connection ===\n\n");
		printf("  ##### ABORTING TRANSMISSION. #####\n");	 
		return 0;
	}
	
	seq = increment_seq(seq, MODULO_SEQ);

	int fd;
	char *filename = malloc(MAXL * sizeof(char));

	//until the received package is EOT ('B'), receive the other packages
	while (r->payload[3] != TYPE_B) {
		r = receive(seq); 	
		seq = increment_seq(seq, MODULO_SEQ);
		
		
		switch (r->payload[3]) {
			case TYPE_F: 
				fd = create_file(r, filename);
				if (fd > 0) 
					printf("=== File %s created"
					       " successfully ===\n\n",
					       filename);
				else {
					printf("=== File %s could not be"
					       " created === \n\n", filename);
					printf(" ##### ABORTING" 
					       "TRASMISSION. #####\n");
					return 0;
				}
				break;
			case TYPE_D:
				write_data(r, fd);	
				break;
			case TYPE_Z:
				close(fd);
				break;
			default:
				break;
		}
	}
	
	printf ("\n  ##### TRANSMISSION ENDED SUCCESSFULY. #####\n"); 		
	return 0;
}
