/* libtls_client.c */

#include <stdio.h>
#include <string.h>
#include <err.h>
#include <errno.h>
#include <tls.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <stdint.h>
#define LEFTROTATE(x, c) (((x) << (c)) | ((x) >> (32 - (c))))
//#######################  Function for MD5 BEGIN   #################
const uint32_t k[64] = {
0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee ,
0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501 ,
0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be ,
0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821 ,
0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa ,
0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8 ,
0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed ,
0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a ,
0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c ,
0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70 ,
0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05 ,
0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665 ,
0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039 ,
0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1 ,
0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1 ,
0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391 };
 
/*r specifies the per-round shift amounts*/
const uint32_t r[] = {7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
                      5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
                      4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
                      6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21};
 
/*leftrotate function definition*/

 
void to_bytes(uint32_t val, uint8_t *bytes)
{
    bytes[0] = (uint8_t) val;
    bytes[1] = (uint8_t) (val >> 8);
    bytes[2] = (uint8_t) (val >> 16);
    bytes[3] = (uint8_t) (val >> 24);
}
 
uint32_t to_int32(const uint8_t *bytes)
{
    return (uint32_t) bytes[0]
        | ((uint32_t) bytes[1] << 8)
        | ((uint32_t) bytes[2] << 16)
        | ((uint32_t) bytes[3] << 24);
}
 
void md5(const uint8_t *initial_msg, size_t initial_len, uint8_t *digest) {
 
    // These vars will contain the hash
    uint32_t h0, h1, h2, h3;
 
    // Message (to prepare)
    uint8_t *msg = NULL;
 
    size_t new_len, offset;
    uint32_t w[16];
    uint32_t a, b, c, d, i, f, g, temp;
 
    // Initialize variables - simple count in nibbles:
    h0 = 0x67452301;
    h1 = 0xefcdab89;
    h2 = 0x98badcfe;
    h3 = 0x10325476;
 
    //Pre-processing:
    //append "1" bit to message    
    //append "0" bits until message length in bits ≡ 448 (mod 512)
    //append length mod (2^64) to message
 
    for (new_len = initial_len + 1; new_len % (512/8) != 448/8; new_len++)
        ;
 
    msg = (uint8_t*)malloc(new_len + 8);
    memcpy(msg, initial_msg, initial_len);
    msg[initial_len] = 0x80; // append the "1" bit; most significant bit is "first"
    for (offset = initial_len + 1; offset < new_len; offset++)
        msg[offset] = 0; // append "0" bits
 
    // append the len in bits at the end of the buffer.
    to_bytes(initial_len*8, msg + new_len);
    // initial_len>>29 == initial_len*8>>32, but avoids overflow.
    to_bytes(initial_len>>29, msg + new_len + 4);
 
    // Process the message in successive 512-bit chunks:
    //for each 512-bit chunk of message:
    for(offset=0; offset<new_len; offset += (512/8)) {
 
        // break chunk into sixteen 32-bit words w[j], 0 ≤ j ≤ 15
        for (i = 0; i < 16; i++)
            w[i] = to_int32(msg + offset + i*4);
 
        // Initialize hash value for this chunk:
        a = h0;
        b = h1;
        c = h2;
        d = h3;
 
        // Main loop:
        for(i = 0; i<64; i++) {
 
            if (i < 16) {
                f = (b & c) | ((~b) & d);
                g = i;
            } else if (i < 32) {
                f = (d & b) | ((~d) & c);
                g = (5*i + 1) % 16;
            } else if (i < 48) {
                f = b ^ c ^ d;
                g = (3*i + 5) % 16;          
            } else {
                f = c ^ (b | (~d));
                g = (7*i) % 16;
            }
 
            temp = d;
            d = c;
            c = b;
            b = b + LEFTROTATE((a + f + k[i] + w[g]), r[i]);
            a = temp;
 
        }
 
        // Add this chunk's hash to result so far:
        h0 += a;
        h1 += b;
        h2 += c;
        h3 += d;
 
    }
 
    // cleanup
    free(msg);
 
    //var char digest[16] := h0 append h1 append h2 append h3 //(Output is in little-endian)
    to_bytes(h0, digest);
    to_bytes(h1, digest + 4);
    to_bytes(h2, digest + 8);
    to_bytes(h3, digest + 12);
}

//###############################   Function for MD5 END######################


void write_file(char* filename, char* buff,int writelen){
	char filepath[2048];
	FILE * pFile = NULL;
	memset(filepath,0,2048);
	strcpy(filepath,"./clientfile/");
	strcat(filepath,filename);
	/*Get File Size*/
    pFile = fopen (filepath,"wb");
    if (pFile==NULL) 
		err (1,"Error opening file");
    else
		fwrite(buff,1,writelen,pFile);
	fclose(pFile);
}


typedef struct {
	char cache[10];
	unsigned char filename[1024];
}send_pkg;

typedef struct{
	char cache[10];
	char realname[1024];
	unsigned char hash_value[17];
} cachechooser;
/*
*caculate hash from file and cache
*/
cachechooser handle_cache_hash(char*cachename,char*filename){
	cachechooser C ;
	char catname[1024] = {0};
	char cache1[10] = {0};
	strcpy(cache1,cachename);
	strcpy(catname,filename);
	strcat(catname,cachename);
	uint8_t result[16];
	for (int i = 0; i < 1000000; i++) {
    	md5((uint8_t*)catname, strlen(catname), result);
    }
	
	memcpy(C.realname,catname,1024);
	memcpy(C.cache,cache1,10);
	memcpy(C.hash_value,result,16);
	C.hash_value[16] = 0x00;
	printf("string after montage:%s\nhash of string is:",catname);
	for (int i = 0; i < 16; i++)
    	printf("%02X", C.hash_value[i]);
	printf("\n");
	return C;

}


send_pkg choosecache(char* filename){
	int i,j;
	cachechooser temp;
	send_pkg Mypkg = {0};
	cachechooser C1 = handle_cache_hash("P1",filename);
	cachechooser C2 = handle_cache_hash("P2",filename);
	cachechooser C3 = handle_cache_hash("P3",filename);
	cachechooser C4 = handle_cache_hash("P4",filename);
	cachechooser C5 = handle_cache_hash("P5",filename);
	cachechooser C6 = handle_cache_hash("P6",filename);
	/*
	insert hash and find the 
	biggest hash value with boomb
	*/
	cachechooser SortC[6] = {C1,C2,C3,C4,C5,C6};	
	for (i = 0;i < 5; i++){
		for (j = 0;j < 5-i ; j++){
			if(strcmp(SortC[j].hash_value,SortC[j+1].hash_value) > 0){
				memcpy(&temp,&SortC[j],sizeof(cachechooser));
				memcpy(&SortC[j],&SortC[j+1],sizeof(cachechooser));
				memcpy(&SortC[j+1],&temp,sizeof(cachechooser));
			}
		}
	}


	printf("the biggest hash owner is %s\n",SortC[5].cache);
	strcpy(Mypkg.cache,SortC[5].cache);
	memcpy(Mypkg.filename,filename,1024);
	return Mypkg;

}

int main(int argc, char *argv[]){

	if(argc != 4){
		printf("usage:./client -p proxyport filename\n");
		exit(0);
	}
	else if(strcmp(argv[1],"-p") != 0)
	{
		printf("usage:./client -p proxyport filename\n");
		exit(0);
	}
	struct tls_config *cfg = NULL;
	struct tls *ctx = NULL;
	ssize_t writelen;
	unsigned char buffer[BUFSIZ];
	char hostname[] = "localhost";
	char *port = argv[2];
	char *filename = argv[3];
	ssize_t r, rc;
	size_t maxread;
	/*
	** initialize libtls
	*/
	send_pkg Mypkg = {0};

	if (tls_init() != 0)
		err(1, "tls_init:");

	/*
	** configure libtls
	*/

	if ((cfg = tls_config_new()) == NULL)
		err(1, "tls_config_new:");

	/* set root certificate (CA) */
	if (tls_config_set_ca_file(cfg, "../../certificates/root.pem") != 0)
		err(1, "tls_config_set_ca_file:");
	else
		printf("Load TLS key OK!\n");

	/*
	** initiate client context
	*/

	if ((ctx = tls_client()) == NULL)
		err(1, "tls_client:");

	/*
	** apply config to context
	*/

	if (tls_configure(ctx, cfg) != 0)
		err(1, "tls_configure: %s", tls_error(ctx));

	/*
	** connect to server
	*/
	printf("connect proxy with TLS...\n");
	if (tls_connect(ctx, hostname, port) != 0)
		err(1, "tls_connect: %s", tls_error(ctx));

	/*
	** send message to server
	*/

	Mypkg = choosecache(filename);

	if((writelen = tls_write(ctx, (char*)&Mypkg, sizeof(send_pkg))) < 0)
		err(1, "tls_write: %s", tls_error(ctx));
	
	printf("Cache choice: [%*.*s]\n", strlen(Mypkg.cache), strlen(Mypkg.cache), Mypkg.cache);
	/*
	** recv file from server
	*/

	r = -1;
	rc = 0;
	maxread = sizeof(buffer) - 1; /* leave room for a 0 byte */
	while ((r != 0) && rc < maxread) {
		r = tls_read(ctx,buffer + rc, maxread - rc);
		if (r == -1) {
			if (errno != EINTR)
				err(1, "read failed");
		} else
			rc += r;
	}
	buffer[rc] = '\0';


	


	/*
	**judge file on the server or not
	*/	
	if(strcmp(buffer,"file@not~exit$") == 0){
		printf("file not on the server\n");
	}
	else if(strcmp(buffer,"file@in~blacklist$") == 0){
		printf("Proxy denied our request\n");
	}
	else{
		
		write_file(filename,buffer,rc);
		
		printf("Success!Check file at dir [./clientfile]\n");
	}

	/*
	** clean up all
	*/

	if (tls_close(ctx) != 0)
		err(1, "tls_close: %s", tls_error(ctx));
	tls_free(ctx);
	tls_config_free(cfg);
	return(0);
}