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

static void usage()
{
	printf("usage:./server -p port\n");
	exit(1);
}

static void kidhandler(int signum) {
	/* signal handler for SIGCHLD */
	waitpid(WAIT_ANY, NULL, WNOHANG);
}


int find_file(char *filename){
	char filepath[2048];
	memset(filepath,0,2048);
	strcpy(filepath,"./serverfile/");
	strcat(filepath,filename);
	printf("filepath is :%s\n",filepath);
	if(access(filepath,F_OK) == 0)
		return 1;
	else
		return 0;
}


void read_file(char* filename,char* buff){
	char filepath[2048];
	FILE * pFile = NULL;
	long size = 0;
	memset(filepath,0,2048);
	strcpy(filepath,"./serverfile/");
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


int main(int argc, char *argv[])
{
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
	u_short port;
	pid_t pid;
	u_long p;
//----------------------------------------
	/*ensure the argument*/
	if (argc != 3)
		usage();
	if(strcmp(argv[1],"-p") != 0)
		usage();
	errno = 0;
	p = strtoul(argv[2], &ep, 10);
	if (*argv[2] == '\0' || *ep != '\0') {
	/* parameter wasn't a number, or was empty */
		fprintf(stderr, "%s - not a number\n", argv[2]);
		usage();
	}
	if ((errno == ERANGE && p == ULONG_MAX) || (p > USHRT_MAX)) {
	/* It's a number, but it either can't fit in an unsigned
		* long, or is too big for an unsigned short
		*/
		fprintf(stderr, "%s - value out of range\n", argv[2]);
		usage();
	}
	/* now safe to do this */
	port = p;
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
	if ((mem = tls_load_file("../../certificates/server.key", &mem_len, "test-server-pass")) == NULL)
		err(1, "tls_load_file(serverkey):");
	if (tls_config_set_key_mem(cfg, mem, mem_len) != 0)
		err(1, "tls_config_set_key_mem:");	
	/*
	** initiate server context
	*/
	printf("print TLS key...\n");
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
			if((readlen = tls_read(cctx, buf, sizeof(buf))) < 0)
				err(1, "tls_read: %s", tls_error(cctx));
			printf("Client need file: [%*.*s]\n", readlen, readlen, buf);



			is_file_exit = find_file(buf);
			if(is_file_exit == 0){
				strcpy(buffer,"file@not~exit$");
				printf("File not at this server\n");
			}
			else{
				read_file(buf,buffer);
				printf("Find file successful,return file\n");
				
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
			
		//	if((writelen = tls_write(ctx, buffer, strlen(buffer))) < 0)
				
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