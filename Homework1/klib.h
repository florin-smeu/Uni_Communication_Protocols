#include "lib.h"

//init package constants
#define SOH 0x01                                                                
#define MAXL 0xfa                                                               
#define TIME 0x05                                                               
#define NPAD 0x00                                                               
#define PADC 0x00                                                               
#define EOL 0x0d                                                                
#define QCTL 0x00                                                               
#define QBIN 0x00                                                               
#define CHKT 0x00                                                               
#define REPT 0x00                                                               
#define CAPA 0x00                                                               
#define R 0x00  
#define MARK 0x0d


//types of packages
#define TYPE_S 'S'
#define TYPE_F 'F'
#define TYPE_D 'D'
#define TYPE_Z 'Z'
#define TYPE_B 'B'
#define TYPE_Y 'Y'
#define TYPE_N 'N'

//receiver file prefix
#define RECV_FILE_PREFIX "recv_"

#define MODULO_SEQ 64


#define S_LEN sizeof(s_pkg)
#define H_LEN sizeof(header)
#define T_LEN sizeof(trailer)
#define P_LEN sizeof(pkg)

#pragma pack(1)

typedef struct {
	unsigned char maxl, time, npad, padc, eol;
	unsigned char qctl, qbin, chkt, rept, capa, r;
} s_data;

typedef struct {
	unsigned char soh, len, seq, type;
} header;

typedef struct {	
	unsigned short check;
	unsigned char mark;
} trailer; 

typedef struct {
	header h;
	s_data d;
	trailer t;
} s_pkg;

typedef struct {
	header h;
	trailer t;
} pkg;

#pragma pack()


