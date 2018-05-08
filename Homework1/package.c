#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include "lib.h"
#include "package.h"


// ########## SENDER ##########

unsigned char* create_s(unsigned char *buffer, char type) 
{       
        s_pkg s;
        
        s.h.soh = SOH;
        s.h.len = S_LEN - 2;
        s.h.seq = 0x00;
        s.h.type = type;

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

        int crc_len = S_LEN - 3;
        unsigned char crc_data[crc_len];
        memcpy(crc_data, &s, crc_len);

        s.t.check = crc16_ccitt(crc_data, crc_len);
        s.t.mark = MARK;
        memcpy(buffer, &s, S_LEN);

        return buffer;
}



unsigned char* create_h(char *filename, int seq) 
{	
	int header_len = H_LEN + strlen(filename) + T_LEN;
	unsigned char *buffer = malloc(header_len * sizeof(unsigned char));

	header h;
	h.soh = SOH;
        h.len = header_len - 2;;
        h.seq = seq;
        h.type = 'F';
	
	memcpy(buffer, &h, H_LEN);	
	memcpy(buffer + H_LEN, filename, strlen(filename));

	int crc_len = header_len - 3;
	unsigned char crc_data[crc_len];
	memcpy(crc_data, buffer, (H_LEN + strlen(filename)));
		
	trailer t;
	t.check = crc16_ccitt(crc_data, crc_len);
	t.mark = MARK;
	
	memcpy(buffer + (header_len - T_LEN), &t, T_LEN);
	
	return buffer;
}

msg* check_timeout(msg* s)
{
	int ctr = 3;
	while (ctr > 0) {
		send_message(s);
		msg* r = receive_message_timeout(TIME * 1000);
		if (r == NULL) 
			ctr--;
		else	
			return r;
		
	}
	return NULL;
}		

msg* send(msg* s) 
{
	msg *r = check_timeout(s);
	if (r == NULL) 
		return NULL;
		
	while (r->payload[3] != 'Y') {
		printf("JOHNULE\n");
		r = check_timeout(s);
		if (r == NULL) 
			return NULL;
	}
	return r;
}		

unsigned char* create_d(unsigned char* data_buffer, int nbytes, int seq) 
{	
	header h;
	h.soh = SOH; 
	h.seq = seq;
	h.len = nbytes + H_LEN + T_LEN - 2;
	h.type = 'D';
	
	int crc_len = nbytes + H_LEN;
	char crc_data[crc_len];
	
	memcpy(crc_data, &h, H_LEN);
	memcpy(crc_data + H_LEN, data_buffer, nbytes);

	trailer t;
	t.check = crc16_ccitt(crc_data, crc_len);
	t.mark = MARK;

	unsigned char* buffer = malloc((H_LEN + nbytes + T_LEN) * sizeof(char));	
	memcpy(buffer, &h, H_LEN);
	memcpy(buffer + H_LEN, data_buffer, nbytes);
	memcpy(buffer + H_LEN + nbytes, &t, T_LEN);
	
	return buffer;
}

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


// ########## RECEIVER ##########

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

int check_crc(msg *r) 
{
	int crc_len = r->len - 3;
	unsigned char crc_data[crc_len];
	memcpy(crc_data, r->payload, crc_len);
	
	unsigned short crc = crc16_ccitt(crc_data, crc_len);
	
	unsigned short actual_crc = r->payload[r->len - 2];
	memcpy(&actual_crc, r->payload + (r->len - 3), 2);
	
	if (actual_crc != crc) {
		printf("INCORRECT CRC [%d]\n", r->payload[2]);
		return -1;
	} else  {
		printf("CORRECT CRC [%d]\n", r->payload[2]);
		return 0;
	}
}

void send_nak(int seq) 
{
	msg s;
	pkg n; 
	n.h.soh = SOH;
	n.h.len = P_LEN - 2;
	n.h.seq = seq;
	n.h.type = 'N';
	
        unsigned char crc_data[H_LEN];
        memcpy(crc_data, &n, H_LEN);

        n.t.check = crc16_ccitt(crc_data, H_LEN);
	n.t.mark = MARK;
	
	memcpy(&s.payload, &n, P_LEN);
	
	send_message(&s); 
}

void send_ack_s()
{	
	msg s;
	
	unsigned char* buffer = malloc(S_LEN * sizeof(unsigned char));
	buffer = create_s(buffer, 'Y');
	
	memcpy(&s.payload, buffer, S_LEN);

	send_message(&s);
}


msg* receive_s()
{	
	msg *r = check_timeout_s();
	
	if (r == NULL)
		return NULL;
		
	while (check_crc(r) < 0) {
		send_nak(0);
		r = check_timeout_s();
		if (r == NULL)
			return NULL;
	}
	
	send_ack_s();
	return r;
}

void send_ack(int seq) 
{
	msg s;
	
	pkg a; 
	a.h.soh = SOH;
	a.h.len = P_LEN - 2;
	a.h.seq = seq;
	a.h.type = 'Y';
	
        unsigned char crc_data[H_LEN];
        memcpy(crc_data, &a, H_LEN);

        a.t.check = crc16_ccitt(crc_data, H_LEN);
	a.t.mark = MARK;
	
	memcpy(&s.payload, &a, P_LEN);
	
	send_message(&s); 	
}	
	 

msg* receive(int seq) 
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

	send_ack(seq);
	return r;
}

int create_file(msg* r) 
{
	int filename_len = r->len - H_LEN - T_LEN;
	char *filename = malloc(filename_len * sizeof(char));
	memcpy(filename, r->payload + H_LEN, filename_len);     
                        	
	char recv_filename[5 + filename_len];
	strcpy(recv_filename, "recv_"); 	
	strcat(recv_filename, filename);
	
	mode_t mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH; 
		
	return open(recv_filename, O_WRONLY|O_CREAT, mode); 
}	

void write_data(msg* r, int fd) 
{
	int data_len = r->len - H_LEN - T_LEN; 
	
	char* data = malloc(data_len * sizeof(char));
	memcpy(data, r->payload + H_LEN, data_len);
	
	write(fd, data, data_len);
}	
	
		 
