/* micro_proxy - really small HTTP proxy
**
** Copyright © 1999 by Jef Poskanzer <jef@mail.acme.com>.
** All rights reserved.
**
** Redistribution and use in source and binary forms, with or without
** modification, are permitted provided that the following conditions
** are met:
** 1. Redistributions of source code must retain the above copyright
**    notice, this list of conditions and the following disclaimer.
** 2. Redistributions in binary form must reproduce the above copyright
**    notice, this list of conditions and the following disclaimer in the
**    documentation and/or other materials provided with the distribution.
**
** THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
** ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
** IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
** ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
** FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
** DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
** OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
** HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
** LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
** OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
** SUCH DAMAGE.
*/

/* micro_proxy */
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

/* tinyhttpd */
#include <arpa/inet.h>
#include <ctype.h>
#include <strings.h>
#include <sys/stat.h>
#include <pthread.h>
#include <sys/wait.h>

#define SERVER_NAME "micro_proxy"
#define SERVER_URL "http://www.acme.com/software/micro_proxy/"
#define PROTOCOL "HTTP/1.0"
#define RFC1123FMT "%a, %d %b %Y %H:%M:%S GMT"
#define TIMEOUT 300

/* Forwards. */
static int open_client_socket( int client, char* hostname, unsigned short port );
static void proxy_http( int client, char* method, char* path, char* protocol, FILE* sockrfp, FILE* sockwfp );
static void proxy_ssl( int client, char* method, char* host, char* protocol, FILE* sockrfp, FILE* sockwfp );
static void sigcatch( int sig );
static void trim( char* line );
static void send_error( int client, int status, char* title, char* extra_header, char* text );
static void send_headers( int client, int status, char* title, char* extra_header, char* mime_type, int length, time_t mod );

/* tinyhttpd */

#define ISspace(x) isspace((int)(x))

void *accept_request(void *);
void bad_request(int);
void error_die(const char *);
int get_line(int, char *, int);
int startup(u_short *);

unsigned alarm_nop(unsigned seconds);
unsigned alarm_nop(unsigned seconds)
{
    return 0;
}

#if defined(AF_INET6) && defined(IN6_IS_ADDR_V4MAPPED)
#define USE_IPV6
#endif

#undef USE_IPV6

static int
open_client_socket( int client, char* hostname, unsigned short port )
{
#ifdef USE_IPV6
    struct addrinfo hints;
    char portstr[10];
    int gaierr;
    struct addrinfo* ai;
    struct addrinfo* ai2;
    struct addrinfo* aiv4;
    struct addrinfo* aiv6;
    struct sockaddr_in6 sa_in;
#else /* USE_IPV6 */
    struct hostent *he;
    struct sockaddr_in sa_in;
#endif /* USE_IPV6 */
    int sa_len, sock_family, sock_type, sock_protocol;
    int sockfd;

    (void) memset( (void*) &sa_in, 0, sizeof(sa_in) );

#ifdef USE_IPV6

    (void) memset( &hints, 0, sizeof(hints) );
    hints.ai_family = PF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    (void) snprintf( portstr, sizeof(portstr), "%d", (int) port );
    if ( (gaierr = getaddrinfo( hostname, portstr, &hints, &ai )) != 0 ) {
        send_error( client, 404, "Not Found", (char*) 0, "Unknown host." );
        return -1;
    }

    /* Find the first IPv4 and IPv6 entries. */
    aiv4 = (struct addrinfo*) 0;
    aiv6 = (struct addrinfo*) 0;
    for ( ai2 = ai; ai2 != (struct addrinfo*) 0; ai2 = ai2->ai_next )
    {
        switch ( ai2->ai_family )
        {
        case AF_INET:
            if ( aiv4 == (struct addrinfo*) 0 )
                aiv4 = ai2;
            break;
        case AF_INET6:
            if ( aiv6 == (struct addrinfo*) 0 )
                aiv6 = ai2;
            break;
        }
    }

    /* If there's an IPv4 address, use that, otherwise try IPv6. */
    if ( aiv4 != (struct addrinfo*) 0 )
    {
        if ( sizeof(sa_in) < aiv4->ai_addrlen )
        {
            (void) fprintf(
                stderr, "%s - sockaddr too small (%lu < %lu)\n",
                hostname, (unsigned long) sizeof(sa_in),
                (unsigned long) aiv4->ai_addrlen );
            return -1;
        }
        sock_family = aiv4->ai_family;
        sock_type = aiv4->ai_socktype;
        sock_protocol = aiv4->ai_protocol;
        sa_len = aiv4->ai_addrlen;
        (void) memmove( &sa_in, aiv4->ai_addr, sa_len );
        goto ok;
    }
    if ( aiv6 != (struct addrinfo*) 0 )
    {
        if ( sizeof(sa_in) < aiv6->ai_addrlen )
        {
            (void) fprintf(
                stderr, "%s - sockaddr too small (%lu < %lu)\n",
                hostname, (unsigned long) sizeof(sa_in),
                (unsigned long) aiv6->ai_addrlen );
            return -1;
        }
        sock_family = aiv6->ai_family;
        sock_type = aiv6->ai_socktype;
        sock_protocol = aiv6->ai_protocol;
        sa_len = aiv6->ai_addrlen;
        (void) memmove( &sa_in, aiv6->ai_addr, sa_len );
        goto ok;
    }

    send_error( client, 404, "Not Found", (char*) 0, "Unknown host." );
    return -1;

ok:
    freeaddrinfo( ai );

#else /* USE_IPV6 */

    he = gethostbyname( hostname );
    if ( he == (struct hostent*) 0 ) {
        send_error( client, 404, "Not Found", (char*) 0, "Unknown host." );
        return -1;
    }
    sock_family = sa_in.sin_family = he->h_addrtype;
    sock_type = SOCK_STREAM;
    sock_protocol = 0;
    sa_len = sizeof(sa_in);
    (void) memmove( &sa_in.sin_addr, he->h_addr, he->h_length );
    sa_in.sin_port = htons( port );

#endif /* USE_IPV6 */

    sockfd = socket( sock_family, sock_type, sock_protocol );
    if ( sockfd < 0 ) {
        send_error( client, 500, "Internal Error", (char*) 0, "Couldn't create socket." );
        return -1;
    }

    if ( connect( sockfd, (struct sockaddr*) &sa_in, sa_len ) < 0 ) {
        send_error( client, 503, "Service Unavailable", (char*) 0, "Connection refused." );
        return -1;
    }

    return sockfd;
}


static void
proxy_http( int client, char* method, char* path, char* protocol, FILE* sockrfp, FILE* sockwfp )
{
    char line[10000], protocol2[10000], comment[10000];
    const char *connection_close = "Connection: close\r\n";
    int first_line, status, ich;
    long content_length, i;

    /* Send request. */
    (void) alarm_nop( TIMEOUT );
    (void) fprintf( sockwfp, "%s %s %s\r\n", method, path, protocol );
    /* Forward the remainder of the request from the client. */
    content_length = -1;
    while ( get_line(client, line, sizeof(line)) > 0 )
    {
        if ( strcmp( line, "\n" ) == 0 || strcmp( line, "\r\n" ) == 0 )
            break;
        (void) fputs( line, sockwfp );
        (void) alarm_nop( TIMEOUT );
        trim( line );
        if ( strncasecmp( line, "Content-Length:", 15 ) == 0 )
            content_length = atol( &(line[15]) );
    }
    (void) fputs( line, sockwfp );
    (void) fflush( sockwfp );
    /* If there's content, forward that too. */
    if ( content_length != -1 )
        for ( i = 0; i < content_length && ( recv(client, &ich, 1, 0) ) > 0; ++i )
            fputc( ich, sockwfp );
    (void) fflush( sockwfp );

    /* Forward the response back to the client. */
    (void) alarm_nop( TIMEOUT );
    content_length = -1;
    first_line = 1;
    status = -1;
    while ( fgets( line, sizeof(line), sockrfp ) != (char*) 0 )
    {
        if ( strcmp( line, "\n" ) == 0 || strcmp( line, "\r\n" ) == 0 )
            break;
        (void) send(client, line, strlen(line), 0);
        (void) alarm_nop( TIMEOUT );
        trim( line );
        if ( first_line )
        {
            (void) sscanf( line, "%[^ ] %d %s", protocol2, &status, comment );
            first_line = 0;
        }
        if ( strncasecmp( line, "Content-Length:", 15 ) == 0 )
            content_length = atol( &(line[15]) );
    }
    /* Add a response header. */
    send(client, connection_close, strlen(connection_close), 0);
    (void) send(client, line, strlen(line), 0);
    /* Under certain circumstances we don't look for the contents, even
    ** if there was a Content-Length.
    */
    if ( strcasecmp( method, "HEAD" ) != 0 && status != 304 )
    {
        /* Forward the content too, either counted or until EOF. */
        for ( i = 0;
                ( content_length == -1 || i < content_length ) && ( ich = getc( sockrfp ) ) != EOF;
                ++i )
        {
            send(client, &ich, 1, 0);
            if ( i % 10000 == 0 )
                (void) alarm_nop( TIMEOUT );
        }
    }
}


static void
proxy_ssl( int client, char* method, char* host, char* protocol, FILE* sockrfp, FILE* sockwfp )
{
    int client_read_fd, server_read_fd, client_write_fd, server_write_fd;
    struct timeval timeout;
    fd_set fdset;
    int maxp1, r;
    char buf[10000];
    const char *connection_established = "HTTP/1.0 200 Connection established\r\n\r\n";

    while ( get_line(client, buf, sizeof(buf)) > 0 )
    {
        if ( strcmp( buf, "\n" ) == 0 || strcmp( buf, "\r\n" ) == 0 )
            break;
    }

    /* Return SSL-proxy greeting header. */
    send(client, connection_established, strlen(connection_established), 0);
    /* Now forward SSL packets in both directions until done. */
    client_read_fd = client;
    server_read_fd = fileno( sockrfp );
    client_write_fd = client;
    server_write_fd = fileno( sockwfp );
    timeout.tv_sec = TIMEOUT;
    timeout.tv_usec = 0;
    if ( client_read_fd >= server_read_fd )
        maxp1 = client_read_fd + 1;
    else
        maxp1 = server_read_fd + 1;
    (void) alarm_nop( 0 );
    for (;;)
    {
        FD_ZERO( &fdset );
        FD_SET( client_read_fd, &fdset );
        FD_SET( server_read_fd, &fdset );
        r = select( maxp1, &fdset, (fd_set*) 0, (fd_set*) 0, &timeout );
        if ( r == 0 ) {
            send_error( client, 408, "Request Timeout", (char*) 0, "Request timed out." );
            return;
        }
        else if ( FD_ISSET( client_read_fd, &fdset ) )
        {
            r = read( client_read_fd, buf, sizeof( buf ) );
            if ( r <= 0 )
                break;
            r = write( server_write_fd, buf, r );
            if ( r <= 0 )
                break;
        }
        else if ( FD_ISSET( server_read_fd, &fdset ) )
        {
            r = read( server_read_fd, buf, sizeof( buf ) );
            if ( r <= 0 )
                break;
            r = write( client_write_fd, buf, r );
            if ( r <= 0 )
                break;
        }
    }
}


static void
sigcatch( int sig )
{
    /* TODO */
    /* send_error( client, 408, "Request Timeout", (char*) 0, "Request timed out." ); */
}


static void
trim( char* line )
{
    int l;

    l = strlen( line );
    while ( line[l-1] == '\n' || line[l-1] == '\r' )
        line[--l] = '\0';
}


static void
send_error( int client, int status, char* title, char* extra_header, char* text )
{
    char buf[10000];
    send_headers( client, status, title, extra_header, "text/html", -1, -1 );
    (void) sprintf( buf, "\
<!DOCTYPE html PUBLIC \"-//W3C//DTD HTML 4.01 Transitional//EN\" \"http://www.w3.org/TR/html4/loose.dtd\">\n\
<html>\n\
  <head>\n\
    <meta http-equiv=\"Content-type\" content=\"text/html;charset=UTF-8\">\n\
    <title>%d %s</title>\n\
  </head>\n\
  <body bgcolor=\"#cc9999\" text=\"#000000\" link=\"#2020ff\" vlink=\"#4040cc\">\n\
    <h4>%d %s</h4>\n\n",
                    status, title, status, title );
    send(client, buf, strlen(buf), 0);
    (void) sprintf( buf, "%s\n\n", text );
    send(client, buf, strlen(buf), 0);
    (void) sprintf( buf, "\
    <hr>\n\
    <address><a href=\"%s\">%s</a></address>\n\
  </body>\n\
</html>\n",
                    SERVER_URL, SERVER_NAME );
    send(client, buf, strlen(buf), 0);
}


static void
send_headers( int client, int status, char* title, char* extra_header, char* mime_type, int length, time_t mod )
{
    time_t now;
    char timebuf[100];
    char buf[10000];


    send(client, buf, strlen(buf), 0);
    sprintf( buf, "%s %d %s\r\n", PROTOCOL, status, title );
    send(client, buf, strlen(buf), 0);
    sprintf( buf, "Server: %s\r\n", SERVER_NAME );
    send(client, buf, strlen(buf), 0);
    now = time( (time_t*) 0 );
    (void) strftime( timebuf, sizeof(timebuf), RFC1123FMT, gmtime( &now ) );
    sprintf( buf, "Date: %s\r\n", timebuf );
    send(client, buf, strlen(buf), 0);
    if ( extra_header != (char*) 0 ) {
        sprintf( buf, "%s\r\n", extra_header );
        send(client, buf, strlen(buf), 0);
    }
    if ( mime_type != (char*) 0 ) {
        sprintf( buf, "Content-Type: %s\r\n", mime_type );
        send(client, buf, strlen(buf), 0);
    }
    if ( length >= 0 ) {
        sprintf( buf, "Content-Length: %d\r\n", length );
        send(client, buf, strlen(buf), 0);
    }
    if ( mod != (time_t) -1 )
    {
        (void) strftime( timebuf, sizeof(timebuf), RFC1123FMT, gmtime( &mod ) );
        sprintf( buf, "Last-Modified: %s\r\n", timebuf );
        send(client, buf, strlen(buf), 0);
    }
    sprintf( buf, "Connection: close\r\n" );
    send(client, buf, strlen(buf), 0);
    sprintf( buf, "\r\n" );
    send(client, buf, strlen(buf), 0);
}

/* tinyhttpd */

/**********************************************************************/
/* A request has caused a call to accept() on the server port to
 * return.  Process the request appropriately.
 * Parameters: the socket connected to the client */
/**********************************************************************/
void *accept_request(void *_client)
{
    int client = (int) (long) _client;
    int numchars;

    char line[10000], method[10000], url[10000], protocol[10000], host[10000], path[10000];
    unsigned short port;
    int iport;
    int sockfd;
    int ssl;
    FILE* sockrfp;
    FILE* sockwfp;

    numchars = get_line(client, line, sizeof(line));
    /* Read the first line of the request. */
    if ( numchars == 0 ) {
        send_error( client, 400, "Bad Request", (char*) 0, "No request found." );
        return NULL;
    }

    /* Parse it. */
    trim( line );
    if ( sscanf( line, "%[^ ] %[^ ] %[^ ]", method, url, protocol ) != 3 ) {
        send_error( client, 400, "Bad Request", (char*) 0, "Can't parse request." );
        return NULL;
    }

    if ( url[0] == '\0' ) {
        send_error( client, 400, "Bad Request", (char*) 0, "Null URL." );
        return NULL;
    }

    if ( strncasecmp( url, "http://", 7 ) == 0 )
    {
        (void) strncpy( url, "http", 4 );       /* make sure it's lower case */
        if ( sscanf( url, "http://%[^:/]:%d%s", host, &iport, path ) == 3 )
            port = (unsigned short) iport;
        else if ( sscanf( url, "http://%[^/]%s", host, path ) == 2 )
            port = 80;
        else if ( sscanf( url, "http://%[^:/]:%d", host, &iport ) == 2 )
        {
            port = (unsigned short) iport;
            *path = '\0';
        }
        else if ( sscanf( url, "http://%[^/]", host ) == 1 )
        {
            port = 80;
            *path = '\0';
        }
        else {
            send_error( client, 400, "Bad Request", (char*) 0, "Can't parse URL." );
            return NULL;
        }
        ssl = 0;
    }
    else if ( strcmp( method, "CONNECT" ) == 0 )
    {
        if ( sscanf( url, "%[^:]:%d", host, &iport ) == 2 )
            port = (unsigned short) iport;
        else if ( sscanf( url, "%s", host ) == 1 )
            port = 443;
        else {
            send_error( client, 400, "Bad Request", (char*) 0, "Can't parse URL." );
            return NULL;
        }
        ssl = 1;
    }
    else {
        send_error( client, 400, "Bad Request", (char*) 0, "Unknown URL type." );
        return NULL;
    }

    /* Get ready to catch timeouts.. */
    (void) signal( SIGALRM, sigcatch );

    /* Open the client socket to the real web server. */
    (void) alarm_nop( TIMEOUT );
    sockfd = open_client_socket( client, host, port );

    if (sockfd >= 0) {
        /* Open separate streams for read and write, r+ doesn't always work. */
        sockrfp = fdopen( sockfd, "r" );
        sockwfp = fdopen( sockfd, "w" );

        if ( ssl )
            proxy_ssl( client, method, host, protocol, sockrfp, sockwfp );
        else
            proxy_http( client, method, path, protocol, sockrfp, sockwfp );

        /* Done. */
        (void) close( sockfd );
    }

    close(client);
    return NULL;
}

/**********************************************************************/
/* Inform the client that a request it has made has a problem.
 * Parameters: client socket */
/**********************************************************************/
void bad_request(int client)
{
    char buf[1024];

    sprintf(buf, "HTTP/1.0 400 BAD REQUEST\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "Content-type: text/html\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "<P>Your browser sent a bad request, ");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "such as a POST without a Content-Length.\r\n");
    send(client, buf, strlen(buf), 0);
}

/**********************************************************************/
/* Print out an error message with perror() (for system errors; based
 * on value of errno, which indicates system call errors) and exit the
 * program indicating an error. */
/**********************************************************************/
void error_die(const char *sc)
{
    perror(sc);
    exit(1);
}

/**********************************************************************/
/* Get a line from a socket, whether the line ends in a newline,
 * carriage return, or a CRLF combination.  Terminates the string read
 * with a null character.  If no newline indicator is found before the
 * end of the buffer, the string is terminated with a null.  If any of
 * the above three line terminators is read, the last character of the
 * string will be a linefeed and the string will be terminated with a
 * null character.
 * Parameters: the socket descriptor
 *             the buffer to save the data in
 *             the size of the buffer
 * Returns: the number of bytes stored (excluding null) */
/**********************************************************************/
int get_line(int sock, char *buf, int size)
{
    int i = 0;
    char c = '\0';
    int n;

    while ((i < size - 1) && (c != '\n'))
    {
        n = recv(sock, &c, 1, 0);
        /* DEBUG printf("%02X\n", c); */
        if (n > 0)
        {
            if (c == '\r')
            {
                n = recv(sock, &c, 1, MSG_PEEK);
                /* DEBUG printf("%02X\n", c); */
                if ((n > 0) && (c == '\n'))
                    recv(sock, &c, 1, 0);
                else
                    c = '\n';
            }
            buf[i] = c;
            i++;
        }
        else
            c = '\n';
    }
    buf[i] = '\0';

    return(i);
}

/**********************************************************************/
/* This function starts the process of listening for web connections
 * on a specified port.  If the port is 0, then dynamically allocate a
 * port and modify the original port variable to reflect the actual
 * port.
 * Parameters: pointer to variable containing the port to connect on
 * Returns: the socket */
/**********************************************************************/
int startup(u_short *port)
{
    int httpd = 0;
    struct sockaddr_in name;

    httpd = socket(PF_INET, SOCK_STREAM, 0);
    if (httpd == -1)
        error_die("socket");
    memset(&name, 0, sizeof(name));
    name.sin_family = AF_INET;
    name.sin_port = htons(*port);
    name.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(httpd, (struct sockaddr *)&name, sizeof(name)) < 0)
        error_die("bind");
    if (*port == 0)  /* if dynamically allocating a port */
    {
        unsigned int namelen = (unsigned int) sizeof(name);
        if (getsockname(httpd, (struct sockaddr *)&name, &namelen) == -1)
            error_die("getsockname");
        *port = ntohs(name.sin_port);
    }
    if (listen(httpd, 5) < 0)
        error_die("listen");
    return(httpd);
}

/**********************************************************************/


int main(int argc, const char **argv)
{
    int server_sock = -1;
    u_short port = 0;
    int client_sock = -1;
    struct sockaddr_in client_name;
    unsigned int client_name_len = (unsigned int) sizeof(client_name);
    pthread_t newthread;

    if (argc == 2)
    {
        port = (u_short) atoi(argv[1]);
    }

    server_sock = startup(&port);
    printf("httpd running on port %d\n", port);

    while (1)
    {
        client_sock = accept(server_sock,
                             (struct sockaddr *)&client_name,
                             &client_name_len);
        if (client_sock == -1)
            error_die("accept");
        /* accept_request(client_sock); */
        if (pthread_create(&newthread , NULL, &accept_request, (void *)(long)client_sock) != 0)
            perror("pthread_create");
    }

    close(server_sock);

    return(0);
}
