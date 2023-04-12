/*                                                  file = tlswebserver_v2.c   */
/*  This is a basic Web server that uses TLSv1.2                               */
/* --------------------------------------------------------------------------- */ 
/*  Notes:                                                                     */
/*     1) Serves HTML, JPEG, and favico.ico files.                             */
/*     2) Uses TLS v. 1.2 and a .crt and .key file to load a certificate.      */
/*     3) The server operates sequentially, within the main thread             */
/*        of execution and does not spin-off threads for each HTTP/TLS request */
/* --------------------------------------------------------------------------- */
/*   Execution notes:                                                          */
/*    1) Execute this program in the directory which will be the default for   */
/*       all file references (i.e., the directory that is considered at        */
/*       "index.html").                                                        */
/*    2) Digital certificate files (.crt and .key) need to be pre-stored       */
/*       into the execution directory. This is necessary for the TLS           */
/*       certificate, incl. sever's public key, to be processed properly and   */
/*       send to the client so that the TLS session is established.            */
/*    3) Open a Web browser and surf http://xxx.xxx.xxx.xxx:443/yyy where      */
/*       xxx.xxx.xxx.xxx is the IP address or hostname of the machine that     */
/*       tlswebserver is executing on and y.y is the requested object,         */
/*       e.g. favicon.ico.                                                     */
/* --------------------------------------------------------------------------- */
/*   Build:                                                                    */
/*     Unix/Mac (BSD): gcc tlswebserver.c -o tlswebserver -lssl -lcrypto       */
/* --------------------------------------------------------------------------- */
/*   Execute: sudo ./tlswebserver 443                                          */
/* --------------------------------------------------------------------------- */
/*   History:  ZGP (2/13/2022) - Genesis from                                  */   
/*             https://aticleworld.com/ssl-server-client-using-openssl-in-c/   */
/*             ZGP (4/14/2022) - Added functionality to serve files            */
/* --------------------------------------------------------------------------- */

#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h> /* Needed for memcpy() and strcpy() */
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <resolv.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <fcntl.h>        /* Needed for file I/O stuff */
#include <sys/stat.h>   /* Needed for file I/O constants */
#define FAIL    -1

/* ----- HTTP response messages -------------------------------------------- */
#define OK_IMAGE  "HTTP/1.1 200 OK\r\nContent-Type:image/jpeg\r\n\r\n"
#define OK_TEXT   "HTTP/1.1 200 OK\r\nContent-Type:text/html\r\n\r\n"
#define NOTOK_404 "HTTP/1.1 404 Not Found\r\nContent-Type:text/html\r\n\r\n"
#define MESS_404  "<html><body><h1>FILE NOT FOUND</h1></body></html>"

#define  BUF_SIZE            4096     /* Buffer size (big enough for a GET) */

/* Create the SSL socket and intialize the socket address structure */
int OpenListener(int port)
{
    int sd;
    struct sockaddr_in addr;
    sd = socket(PF_INET, SOCK_STREAM, 0);
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;
    if (bind(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0 )
    {
        perror("Can't bind to the specified port.");
        abort();
    }
    if ( listen(sd, 10) != 0 )
    {
        perror("Can't configure listening port.");
        abort();
    }
    return sd;
}
int isRoot()
{
    if (getuid() != 0)
    {
        return 0;
    }
    else
    {
        return 1;
    }
}
SSL_CTX* InitServerCTX(void)
{
    SSL_METHOD *method; /* data structure describing the OpenSSL library functions for */
	                    /* protocol versions (e.g. SSLv1, SSLv2 or TLSv1) */
						/* SSL_METHOD is needed to create an SSL_CTX object */
    SSL_CTX *ctx;   /* SSL_CTX context object contains options for certificates, algorithms, etc. */
	            	/* can be assigned to an SSL object AFTER a network connection has been created. */
    OpenSSL_add_all_algorithms();  /* load & register all cryptos, etc. */
    SSL_load_error_strings();   /* load all error messages */
    method = TLSv1_2_server_method();  /* create new server-method instance */
    ctx = SSL_CTX_new(method);   /* create new context object from method */
    if ( ctx == NULL )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    return ctx;
}
void LoadCertificates(SSL_CTX* ctx, char* CertFile, char* KeyFile)
{
    /* set the local certificate from CertFile */
    if ( SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0 )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    /* set the private key from KeyFile (may be the same as CertFile) */
    if ( SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0 )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    /* verify private key */
    if ( !SSL_CTX_check_private_key(ctx) )
    {
        fprintf(stderr, "Private key does not match the public certificate.\n");
        abort();
    }
}
void ShowCerts(SSL* ssl)
{
    X509 *cert;
    char *line;
    cert = SSL_get_peer_certificate(ssl); /* Get certificates (if available) */
    if ( cert != NULL )
    {
        printf("Server certificates:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("Subject: %s\n", line);
        free(line);
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("Issuer: %s\n", line);
        free(line);
        X509_free(cert);
    }
    else
        printf("No certificates.\n");
}
 
int main(int count, char *Argc[])
{
    SSL_CTX *ctx;
    int server;
    char *portnum;

/* Only root users have the permission to run the server */
    if(!isRoot())
    {
        printf("This program must be executed as root/sudo user!!");
        exit(0);
    }
    if ( count != 2 )
    {
        printf("Usage: %s <portnum>\n", Argc[0]);
        exit(0);
    }
    /* Initialize the SSL library */
    SSL_library_init();
    portnum = Argc[1];
    ctx = InitServerCTX();        /* initialize SSL */
    LoadCertificates(ctx, "n01457800.crt", "n01457800.key"); /* load certificate */
    server = OpenListener(atoi(portnum));    /* create server socket */
    while (1)
    {
        struct sockaddr_in addr;
        socklen_t len = sizeof(addr);
        SSL *ssl;
        int client = accept(server, (struct sockaddr*)&addr, &len);  /* accept connection as usual */
        if (client == -1)
        {
			printf("ERROR - Unable to create a socket \n");
			exit(1);
        }
 
		printf("Connection: %s:%d\n",inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
        ssl = SSL_new(ctx);           /* get new SSL state with context */
        SSL_set_fd(ssl, client);      /* set connection socket to SSL state */
		Servlet(ssl);                 /* service connection */
              
    }
    close(server);          /* close server socket */
    SSL_CTX_free(ctx);      /* release context & free up the allocated memory if the reference count has reached 0 */
}

void Servlet(SSL* ssl) /* Serve the connection -- threadable, but not implemented as such */
{
    char 	buf[BUF_SIZE] = {0};
	char    html_buf[BUF_SIZE];   /* Output buffer for HTML response */
    int 	sd, bytes;
	int 	fh;
	char    command[BUF_SIZE];    /*  Command buffer */
	char    file_name[BUF_SIZE];  /*  File name buffer */
	int     buf_len;              /*  Buffer length for file reads */
	
	const char* ServerResponse="<Body><Name>CNT4406</Name> <br><year>Spring 2022</year><br>This is a simple Web sever using SSLv1.2 to serve this short HTML page over an encrypted connection. Note that if you use a packet sniffer such as WireShark, you will not see any HTTP packets as the HTTP header is encrypted within the TLS payload.<br><Author>Z.Prodanoff</Author></Body>";
    if ( SSL_accept(ssl) == FAIL )     /* do SSL-protocol accept */
        ERR_print_errors_fp(stderr);
    else
    {
        ShowCerts(ssl);        /* get certificates */
        bytes = SSL_read(ssl, buf, sizeof(buf)); /* get request */
        buf[bytes] = '\0';
        printf("Client msg: \%s\"\n", buf);
        if ( bytes > 0 )
        {
			/*  Receive the (presumed) GET request from the Web browser */
			/*  Parse out the command from the (presumed) GET request and filename */
			sscanf(buf, "%s %s \n", command, file_name);
			/*  Check if command really is a GET, if not then bail-out */
			if (strcmp(command, "GET") != 0)
			{
				printf("ERROR - Not a GET --- received command = '%s' \n", command);
				close(ssl);
				pthread_exit(NULL);
			}
			fh = open(&file_name[1], O_RDONLY, S_IREAD | S_IWRITE);
			if (fh == -1)
			{
				printf("File '%s' not found --- sending an HTTP 404 \n", &file_name[1]);
				strcpy(html_buf, NOTOK_404);
				SSL_write(ssl, html_buf, strlen(html_buf)); /* send reply */

				strcpy(html_buf, MESS_404);
				SSL_write(ssl, html_buf, strlen(html_buf)); /* send reply */
				close(ssl);
				return;
			}

			/* Generate and send the response */
			printf("Sending file '%s' \n", &file_name[1]);
 
			if ((strstr(file_name, ".jpg")|| strstr(file_name, ".ico") ||
                strstr(file_name, ".png" 
            
            )) != NULL)
			{
				strcpy(html_buf, OK_IMAGE);
				printf("Recognized as IMAGE \n");
			}
			else
			{
				strcpy(html_buf, OK_TEXT);
				printf("Recognized as TEXT \n");
			}
						
			send(ssl, html_buf, strlen(html_buf), 0);
	
			while(1)
			{
				buf_len = read(fh, html_buf, BUF_SIZE);
				if (buf_len == 0) 
					break;
				SSL_write(ssl, html_buf, buf_len); /* send reply */
					
			}
			
			/* Close the file, close the client socket */
			close(fh);
			close(ssl);
		}
		else
			ERR_print_errors_fp(stderr);
			
	}
    sd = SSL_get_fd(ssl);       /* get socket connection */
    SSL_free(ssl);         /* release SSL state */
    close(sd);          /* close connection */
}
