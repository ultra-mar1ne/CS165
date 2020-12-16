#include <stdio.h>
#include <time.h>
#include <err.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <tls.h>
#include <sys/wait.h>
#include <limits.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#ifndef BLOOMFILTER_H_INCLUDED
#define BLOOMFILTER_H_INCLUDED

#ifdef __cplusplus
extern "C" {
#endif

#include <assert.h>
#include <fcntl.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#define BLOOMFILTER_VERSION    "1.0.0"
//################################code for BloomFilter BEGIN ####################
struct bloomfilter_t
{
    // These fields are part of the public interface of this structure.
    // Client code may read these values if desired. Client code MUST NOT
    // modify any of these.
    int entries;
    double error;
    int bits;
    int bytes;
    int hashes;

    // Fields below are private to the implementation. These may go away or
    // change incompatibly at any moment. Client code MUST NOT access or rely
    // on these.
    double bpe;
    unsigned char * bf;
    int ready;
};

static unsigned int murmurhash2 (const void * key, int len, const unsigned int seed)
{
	// 'm' and 'r' are mixing constants generated offline.
	// They're not really 'magic', they just happen to work well.

	const unsigned int m = 0x5bd1e995;
	const int r = 24;

	// Initialize the hash to a 'random' value

	unsigned int h = seed ^ len;

	// Mix 4 bytes at a time into the hash

	const unsigned char * data = (const unsigned char *)key;

	while (len >= 4) {
		unsigned int k = *(unsigned int *)data;

		k *= m;
		k ^= k >> r;
		k *= m;

		h *= m;
		h ^= k;

		data += 4;
		len -= 4;
	}

	// Handle the last few bytes of the input array

	switch (len) {
	case 3:
        h ^= data[2] << 16;
	case 2:
        h ^= data[1] << 8;
	case 1:
        h ^= data[0];
	    h *= m;
	};

	h ^= h >> 13;
	h *= m;
	h ^= h >> 15;

	return h;
}

static int bloom_test_bit_set_bit (unsigned char * buf, unsigned int x, int set_bit)
{
    unsigned int byte = x >> 3;

    // expensive memory access
    unsigned char c = buf[byte];

    unsigned int mask = 1 << (x % 8);

    if (c & mask) {
        return 1;
    } else {
        if (set_bit) {
            buf[byte] = c | mask;
        }
        return 0;
    }
}

static int bloom_check_add (struct bloomfilter_t * bloom, const void * buffer, int len, int add)
{
    if (bloom->ready == 0) {
        printf("bloom at %p not initialized!\n", (void *)bloom);
        return -1;
    }

    int hits = 0;
    register unsigned int a = murmurhash2(buffer, len, 0x9747b28c);
    register unsigned int b = murmurhash2(buffer, len, a);
    register unsigned int x;
    register unsigned int i;

    for (i = 0; i < (unsigned int) bloom->hashes; i++) {
        x = (a + i*b) % bloom->bits;
        if (bloom_test_bit_set_bit(bloom->bf, x, add)) {
            hits++;
        }
    }

    if (hits == bloom->hashes) {
        // 1 == element already in (or collision)
        return 1;
    }

    return 0;
}

static int bloomfilter_init (struct bloomfilter_t * bloom, int entries, double error)
{
    bloom->ready = 0;

    if (entries < 1 || error == 0) {
        return 1;
    }

    bloom->entries = entries;
    bloom->error = error;

    double num = log(bloom->error);
    double denom = 0.480453013918201; // ln(2)^2
    bloom->bpe = -(num / denom);

    double dentries = (double)entries;
    bloom->bits = (int)(dentries * bloom->bpe);

    if (bloom->bits % 8) {
        bloom->bytes = (bloom->bits / 8) + 1;
    } else {
        bloom->bytes = bloom->bits / 8;
    }

    bloom->hashes = (int)ceil(0.693147180559945 * bloom->bpe);  // ln(2)

    bloom->bf = (unsigned char *)calloc(bloom->bytes, sizeof(unsigned char));
    if (bloom->bf == NULL) {
        return 1;
    }

    bloom->ready = 1;
    return 0;
}

static int bloomfilter_check (struct bloomfilter_t * bloom, const void * buffer, int len)
{
    return bloom_check_add(bloom, buffer, len, 0);
}

static int bloomfilter_add (struct bloomfilter_t * bloom, const void * buffer, int len)
{
    return bloom_check_add(bloom, buffer, len, 1);
}

static void bloomfilter_print (struct bloomfilter_t * bloom)
{
    printf("bloom at %p\n", (void *) bloom);
    printf(" .entries = %d\n", bloom->entries);
    printf(" .error = %f\n", bloom->error);
    printf(" .bits = %d\n", bloom->bits);
    printf(" .bits-per-elem = %f\n", bloom->bpe);
    printf(" .bytes = %d\n", bloom->bytes);
    printf(" .hash-functions = %d\n", bloom->hashes);
}

static void bloomfilter_free (struct bloomfilter_t * bloom)
{
    if (bloom->ready) {
        free(bloom->bf);
    }
    bloom->ready = 0;
}

static const char * bloomfilter_version (void)
{
    return BLOOMFILTER_VERSION;
}

#ifdef __cplusplus
}
#endif

#endif
//################################  code for BloomFilter END  ####################

typedef struct{
    char name[10];
    char filepath[256];
    struct bloomfilter_t bloom;
}Cache;

Cache P1,P2,P3,P4,P5,P6;

typedef struct {
	char cache[10];
	unsigned char filename[1024];
}recv_pkg;

void init_cache(){
    strcpy(P1.name,"P1");
    strcpy(P2.name,"P2");
    strcpy(P3.name,"P3");
    strcpy(P4.name,"P4");
    strcpy(P5.name,"P5");
    strcpy(P6.name,"P6");
    strcpy(P1.filepath,"./proxyfile/P1/");
    strcpy(P2.filepath,"./proxyfile/P2/");
    strcpy(P3.filepath,"./proxyfile/P3/");
    strcpy(P4.filepath,"./proxyfile/P4/");
    strcpy(P5.filepath,"./proxyfile/P5/");
    strcpy(P6.filepath,"./proxyfile/P6/");
    memset(&(P1.bloom),0,sizeof(struct bloomfilter_t));
    memset(&(P2.bloom),0,sizeof(struct bloomfilter_t));
    memset(&(P3.bloom),0,sizeof(struct bloomfilter_t));   
    memset(&(P4.bloom),0,sizeof(struct bloomfilter_t));
    memset(&(P5.bloom),0,sizeof(struct bloomfilter_t));
    memset(&(P6.bloom),0,sizeof(struct bloomfilter_t));  
    bloomfilter_init(&(P1.bloom), 30000, 0.01);
    bloomfilter_init(&(P2.bloom), 30000, 0.01);
    bloomfilter_init(&(P3.bloom), 30000, 0.01);
    bloomfilter_init(&(P4.bloom), 30000, 0.01);
    bloomfilter_init(&(P5.bloom), 30000, 0.01);
    bloomfilter_init(&(P6.bloom), 30000, 0.01);
}
/*
add all filename in blacklist
*/
void add_balcklist(char *file){
    bloomfilter_add(&(P1.bloom), file, strlen(file));
    bloomfilter_add(&(P2.bloom), file, strlen(file));
    bloomfilter_add(&(P3.bloom), file, strlen(file));
    bloomfilter_add(&(P4.bloom), file, strlen(file));
    bloomfilter_add(&(P5.bloom), file, strlen(file));
    bloomfilter_add(&(P6.bloom), file, strlen(file));
}

int open_blacklist(char* filePath){
    char data[100];
    FILE *fp=fopen(filePath,"r");
    if(!fp)
    {
        printf("can't open file\n");
        return 0;
    }
    while(!feof(fp))
    {
        fscanf(fp,"%s",&data);
        add_balcklist(data);
    }
    printf("\n");
    fclose(fp);
    return 1;
}
void fin_cache(){
    bloomfilter_free(&(P1.bloom));
    bloomfilter_free(&(P2.bloom));
    bloomfilter_free(&(P3.bloom));
    bloomfilter_free(&(P4.bloom));
    bloomfilter_free(&(P5.bloom));
    bloomfilter_free(&(P6.bloom));
}

static void kidhandler(int signum) {
	/* signal handler for SIGCHLD */
	waitpid(WAIT_ANY, NULL, WNOHANG);
}
//############### Function about handle file BEGIN ###############
int find_file(char *filename,char* filepath0){
	char filepath[2048];
	memset(filepath,0,2048);
	strcpy(filepath,filepath0);
	strcat(filepath,filename);
	printf("filepath is :%s\n",filepath);
	if(access(filepath,F_OK) == 0)
		return 1;
	else
		return 0;
}

void read_file(char* filename,char* filepath0,char* buff){
	char filepath[2048];
	FILE * pFile = NULL;
	long size = 0;
	memset(filepath,0,2048);
	strcpy(filepath,filepath0);
	strcat(filepath,filename);
	/*Get File Size*/
    pFile = fopen (filepath,"rb");
    if (pFile==NULL) 
		err (1,"Error opening file");
    else{
    fseek (pFile, 0, SEEK_END);
    size=ftell (pFile);
	fseek (pFile, 0, SEEK_SET);
	}
	fread(buff,1,size,pFile);

	fclose(pFile);
}

void write_file(char* filename, char* buff,int writelen,char *filepath0){
	char filepath[2048] = {0};
	FILE * pFile = NULL;
	strcpy(filepath,filepath0);
	strcat(filepath,filename);
	/*Get File Size*/
    printf("Write file at this path:%s\n",filepath);
    pFile = fopen (filepath,"wb");
    if (pFile==NULL) 
		err (1,"Error opening file");
    else
		fwrite(buff,1,writelen,pFile);
	fclose(pFile);
}
//############### Function about handle file END ###############

ssize_t ask_server(unsigned char buffer[BUFSIZ],char *hostname,char *port,char *filename){
    printf("ask server for file\n");
    struct tls_config *cfg = NULL;
	struct tls *ctx = NULL;
	ssize_t writelen;
	ssize_t r,rc;
	size_t maxread;
	/*
	** initialize libtls
	*/

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

	if (tls_connect(ctx, hostname, port) != 0)
		err(1, "tls_connect: %s", tls_error(ctx));

	/*
	** send message to server
	*/
	if((writelen = tls_write(ctx, filename , strlen(filename))) < 0)
		err(1, "tls_write: %s", tls_error(ctx));

	printf("sent file name to server: [%*.*s]\n", strlen(filename), strlen(filename), filename);
	/*
	** recv file from server
	*/

	//if((readlen = tls_read(ctx, buf, sizeof(buf))) < 0)
	//	err(1, "tls_read: %s", tls_error(ctx));

	r = -1;
	rc = 0;
    memset(buffer,0,BUFSIZ);
	maxread = BUFSIZ - 1; /* leave room for a 0 byte */
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
		printf("file not in the server\n");
	}
	else{
		printf("Success!server returned file\n",buffer);
	}

	/*
	** clean up all
	*/

	if (tls_close(ctx) != 0)
		err(1, "tls_close: %s", tls_error(ctx));
	tls_free(ctx);
	tls_config_free(cfg);
    return rc;
}

//################ function for answer the client and test blacklist BEGIN ######
int listen_proxy(u_short port,char * serverhost,char* serverport)
{   Cache *p;
    int file_in_black_list = 0;
    recv_pkg recvfile;
	struct tls_config *cfg = NULL;
	struct tls *ctx = NULL, *cctx = NULL;
	uint8_t *mem;
	size_t mem_len;
	ssize_t readlen;
	unsigned char buf[BUFSIZ];
//--------------------------------
	struct sockaddr_in sockname, client;
	char buffer[BUFSIZ] = {0}, *ep;
	struct sigaction sa;
	int sd,is_file_exit;
	socklen_t clientlen;
	pid_t pid;
//----------------------------------------
	/*ensure the argument*/
	/* now safe to do this */

	/*
	** initialize libtls
	*/
	if (tls_init() != 0)
		err(1, "tls_init:");
	/*
	** configure libtls
	*/
	if ((cfg = tls_config_new()) == NULL)
		err(1, "tls_config_new:");
	/* set root certificate (CA) */
	if ((mem = tls_load_file("../../certificates/root.pem", &mem_len, NULL)) == NULL)
		err(1, "tls_load_file(ca):");
	if (tls_config_set_ca_mem(cfg, mem, mem_len) != 0)
		err(1, "tls_config_set_ca_mem:");
	/* set server certificate */
	if ((mem = tls_load_file("../../certificates/server.crt", &mem_len, NULL)) == NULL)
		err(1, "tls_load_file(server):");
	if (tls_config_set_cert_mem(cfg, mem, mem_len) != 0)
		err(1, "tls_config_set_cert_mem:");	
	/* set server private key */
    printf("load TLS key...\n");
	if ((mem = tls_load_file("../../certificates/server.key", &mem_len, "test-server-pass")) == NULL)
		err(1, "tls_load_file(serverkey):");
	if (tls_config_set_key_mem(cfg, mem, mem_len) != 0)
		err(1, "tls_config_set_key_mem:");	
	/*
	** initiate server context
	*/
	if ((ctx = tls_server()) == NULL)
		err(1, "tls_server:");
	/*
	** apply config to context
	*/
	if (tls_configure(ctx, cfg) != 0)
		err(1, "tls_configure: %s", tls_error(ctx));
	/*
	** create and accept socket
	*/
//-------------------------------------------------------------------------------
	printf("setting up socket ...\n");
	memset(&sockname, 0, sizeof(sockname));
	sockname.sin_family = AF_INET;
	sockname.sin_port = htons(port);
	sockname.sin_addr.s_addr = htonl(INADDR_ANY);
	sd=socket(AF_INET,SOCK_STREAM,0);
	if ( sd == -1)
		err(1, "socket failed");

	if (bind(sd, (struct sockaddr *) &sockname, sizeof(sockname)) == -1)
		err(1, "bind failed");

	if (listen(sd,3) == -1)
		err(1, "listen failed");
		sa.sa_handler = kidhandler;
        sigemptyset(&sa.sa_mask);
	/*
	 * we want to allow system calls like accept to be restarted if they
	 * get interrupted by a SIGCHLD
	 */
        sa.sa_flags = SA_RESTART;
        if (sigaction(SIGCHLD, &sa, NULL) == -1)
                err(1, "sigaction failed");

	/*
	 * finally - the main loop.  accept connections and deal with 'em
	 */
    for(;;){
        int clientsd;
        clientlen = sizeof(&client);
        clientsd = accept(sd, (struct sockaddr *)&client, &clientlen);
        if (clientsd == -1)
            err(1, "accept failed");
        /*
            * We fork child to deal with each connection, this way more
            * than one client can connect to us and get served at any one
            * time.
            */

        pid = fork();
        if (pid == -1)
                err(1, "fork failed");
        if (pid == 0){
            ssize_t written,w;
            printf("accept socket with tls...\n");
            if (tls_accept_socket(ctx, &cctx, clientsd) != 0)
                err(1, "tls_accept_socket: %s", tls_error(ctx));
                /*
                ** receive message from client
                */
            printf("waiting message from client ...\n");
            if((readlen = tls_read(cctx, &recvfile, sizeof(recv_pkg))) < 0)
                err(1, "tls_read: %s", tls_error(cctx));
            printf("Client need file: [%*.*s]\n", strlen(recvfile.filename), strlen(recvfile.filename), recvfile.filename);
            printf("Client need cache: [%*.*s]\n", strlen(recvfile.cache), strlen(recvfile.cache), recvfile.cache);
                /*
                use which cache and judge blacklist
                */
            if(strcmp(recvfile.cache,P1.name) == 0){
                printf("Choose cache P1\n");
                if (bloomfilter_check(&(P1.bloom), recvfile.filename, strlen(recvfile.filename))) {
                    file_in_black_list = 0;
                } else {
                    file_in_black_list = 1;
                    p = &P1;
                }            
            }
            else if(strcmp(recvfile.cache,P2.name) == 0){
                printf("Choose cache P2\n");
                if (bloomfilter_check(&(P2.bloom), recvfile.filename, strlen(recvfile.filename))) {
                    file_in_black_list = 0;
                } else {
                    file_in_black_list = 1;
                    p = &P2;
                }                    
            }
            else if (strcmp(recvfile.cache,P3.name) == 0){
                printf("Choose cache P3\n");
                if (bloomfilter_check(&(P3.bloom), recvfile.filename, strlen(recvfile.filename))) {
                    file_in_black_list = 0;
                } else {
                    file_in_black_list = 1;
                    p = &P3;
                }                    
            }
            else if (strcmp(recvfile.cache,P4.name) == 0){
                printf("Choose cache P4\n");
                if (bloomfilter_check(&(P4.bloom), recvfile.filename, strlen(recvfile.filename))) {
                    file_in_black_list = 0;
                } else {
                    file_in_black_list = 1;
                    p = &P4;
                }                    
            }
            else if (strcmp(recvfile.cache,P5.name) == 0){
                printf("Choose cache P5\n");
                if (bloomfilter_check(&(P5.bloom), recvfile.filename, strlen(recvfile.filename))) {
                    file_in_black_list = 0;
                } else {
                    file_in_black_list = 1;
                    p = &P5;
                }                    
            }            
            else if (strcmp(recvfile.cache,P6.name) == 0){
                printf("Choose cache P6\n");
                if (bloomfilter_check(&(P6.bloom), recvfile.filename, strlen(recvfile.filename))) {
                    file_in_black_list = 0;
                } else {
                    file_in_black_list = 1;
                    p = &P6;
                }                    
            }
            /*the situation that file is in blacklist*/
            memset(buffer,0,BUFSIZ);
            if(file_in_black_list == 0){
                strcpy(buffer,"file@in~blacklist$");
                printf("This file is in black-list\n");
            }
            else{
                is_file_exit = find_file(recvfile.filename,(*p).filepath);
                if(is_file_exit == 0){
                    /*
                    file not in this cache,
                    ask server for file 
                    */
                    ssize_t writelen = ask_server(buffer,serverhost,serverport,recvfile.filename);
                    
                    if(strcmp(buffer,"file@not~exit$") != 0){
                        printf("write file at local cache,writelen:%d\n",writelen);
                        write_file(recvfile.filename,buffer,writelen,(*p).filepath);
                        printf("return file to client\n");
                    }else{
                        printf("Can't find file at local and in Server\n");
                    }
                    


                    //strcpy(buffer,"file@not~exit$");
                }

                    
                else{
                    printf("File is in this cache,return file\n");
                    read_file(recvfile.filename,(*p).filepath,buffer); 
                }
            }
            /*
            **send back my file
            */
            w = 0;
            written = 0;
            while(written < strlen(buffer)){
                    
                w = tls_write(cctx,buffer+written,strlen(buffer) - written);
                if (w == -1){
                    if (errno != EINTR)
                        err(1, "tls_write: %s", tls_error(cctx));
                }
                else{
                    
                    //printf("sent message: [%*.*s]\n", w, w, buffer);
                    written += w;
                }
                    
            }
                
            if (tls_close(cctx) != 0)
                err(1, "tls_close: %s", tls_error(cctx));
            tls_free(cctx);
            exit(0);
        }
        close(clientsd);
    }
//-------------------------------------------------------------
	/*
	** clean up all
	*/

	tls_free(ctx);
	tls_config_free(cfg);

	return(0);
}
//################ function for answer the client and test blacklist END   ######



int main(int argc,char *argv[]){
    if (argc != 4){
        printf("usage:./proxy -p proxyport serverport\n");
        exit(0);
    }
    if (strcmp(argv[1],"-p") != 0){
        printf("usage:./proxy -p proxyport serverport\n");
        exit(0);
    }
    char serverport[10] = {0};
    char servername[1024] = {0};
    u_short proxyport;
	char* ep;
	u_long p;
    sscanf(argv[3],"%[^:]:%[^:]",servername,serverport);
    p = strtoul(argv[2], &ep, 10);
	if (*argv[2] == '\0' || *ep != '\0') {
	/* parameter wasn't a number, or was empty */
		fprintf(stderr, "%s - not a number\n", argv[2]);
		exit(0);
	}
	if ((errno == ERANGE && p == ULONG_MAX) || (p > USHRT_MAX)) {
	/* It's a number, but it either can't fit in an unsigned
		* long, or is too big for an unsigned short
		*/
		fprintf(stderr, "%s - value out of range\n", argv[2]);
		exit(0);
	}
	/* now safe to do this */
	proxyport = p;
    init_cache();
    open_blacklist("./blacklist.txt");
    add_balcklist("test");
    listen_proxy(proxyport,servername,serverport);
    fin_cache();
    return 0;
}
