#include <sys/types.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>
#include <malloc.h>
#include <fcntl.h>
#include <signal.h>

#include "clientObject.h"
#include "listen.h"
#include "defines.h"
#include "socketsNetLib.h"
#include "threadPool.h"
#include "encryption.h"
#include "send.h"

struct thread_pool *tcp_thread_pool = NULL;
struct thread_pool *udp_thread_pool = NULL;

// global sslContext TCP... move this?
static SSL_CTX *ssl_context = NULL;

static void sigpipe_ignorer();

// Global switch for what type of TCP recv() we'll be doing
static enum packet_receiver_type packet_receiver_type = PACKET_RECEIVER_TCP;

typedef ssize_t (*packet_receiver_t)(struct packet_reception_args*);
static inline ssize_t recv_tcp_unencrypted (struct packet_reception_args *restrict args);
static inline ssize_t recv_tcp_encrypted   (struct packet_reception_args *restrict args);
static packet_receiver_t recv_variants[PACKET_RECEIVER_COUNT] = 
{ 
            recv_tcp_unencrypted,
            recv_tcp_encrypted
};

static void destroy_packet_reception_args (struct packet_reception_args **args);

void set_tcp_receive_type(enum packet_receiver_type type)
{
    packet_receiver_type = type;
}

int listen_for_udp(struct host *localhost, void (*packet_handler)(char*, ssize_t, struct host*))    //Should be called on it's own thread as the while loop is blocking 
{    
    const socketfd_t sockfd                     = create_socket(SOCK_DEFAULT_UDP);
    struct host           remotehost                 = { 0 };
    ssize_t        num_bytes                   = 0;
    socklen_t      len                        = 0;
    char           buffer[PACKET_BUFFER_SIZE] = { 0 };

    if (FAILURE(bind_socket(sockfd, 
                           localhost)))
    {
        perror("Failed to listen for UDP \n");
        return ERROR;
    }

    set_communicating(localhost);
    set_communicating(&remotehost);

    len = sizeof(localhost->address);
    // Need to cast the pointer to a sockaddr type to satisfy the syscall
    struct sockaddr* remote_address = ( struct sockaddr *)&remotehost.address;

    while(is_communicating(localhost)) {
        num_bytes = recvfrom(sockfd, 
                            buffer, 
                            PACKET_BUFFER_SIZE, 
                            MSG_WAITALL, 
                            remote_address, 
                           &len);

        if (num_bytes < PACKET_BUFFER_SIZE) {
            buffer[num_bytes] = '\0';    // Null terminate the received data
        }

        if (num_bytes == 0) {
            printf("Transmission finished\n");
            break;
        }
        // TODO: this is currently blocking and should run in it's own thread from
        // the pool, but I don't need UDP right now and even if I did it should be _okay_
        // for a small amount of hosts.
        packet_handler(buffer, num_bytes, &remotehost);
    }

    if (is_communicating(localhost)) {
        close_connections(localhost);
    }
    if (is_communicating(&remotehost)) {
        close_connections(&remotehost);
    }

    return SUCCESS;
}
static int try_accept_connection(struct host *localhost, struct host *remotehost)
{
    socklen_t        addr_len       = 0;
    struct sockaddr *remote_address = NULL;
    socketfd_t         sockfd        = 0;
    int              err           = 0;
    // Need to cast the type because that's
    // just how sockets work
    remote_address = ( struct sockaddr *)&remotehost->address;
    addr_len       = sizeof(remotehost->address);

    sockfd = 
    create_socket(accept(get_socket(localhost), 
                 remote_address, 
                 &addr_len));
    if (sockfd < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return RECV_TRYAGAIN;
        }
        return RECV_ERROR;
    }
    err =
    set_socket_non_block(sockfd);
    if (err != 0) {
        return RECV_ERROR;
    }
    set_socket        (remotehost, sockfd);
    set_communicating (remotehost);
    return 0;
}

static void sigpipe_ignorer()
{
    static sigset_t set;
    sigemptyset (&set);
    sigaddset(&set, SIGPIPE);
    if (pthread_sigmask(SIG_BLOCK, &set, NULL) != 0) {
        fprintf(stderr, "\nError setting SIGPIPE signal mask. Exiting...\n");
        exit(1);
    }
}
/*
 * Core TCP listening function.
 * Call it once and it will block
 * and listen until the localhost
 * is set not to listen any more.
 * */
int listen_for_tcp(struct host *localhost, 
                 void (*packet_handler)(char*, ssize_t, struct host*))
{
#ifdef DEBUG
    fprintf(stderr, "\nListening for TCP connections...");
#endif
    struct packet_reception_args *reception_args = NULL;
    struct host                *remotehost    = NULL;
    int                  er            = 0;

    sigpipe_ignorer();

    create_thread_pool  (&tcp_thread_pool);
    set_socket         (localhost, create_socket(SOCK_DEFAULT_TCP));
    set_socket_non_block (get_socket(localhost));

    /* TLS setup */ 
    if (packet_receiver_type == PACKET_RECEIVER_TLS) {
        ssl_context = create_ssl_context();
        configure_ssl_context(ssl_context);
    }
    /* --------- */

    if (FAILURE(bind_socket(get_socket(localhost), localhost))) {
        perror("\nFailed to listen for TCP");
        return ERROR;
    }
    set_communicating(localhost);
    if (FAILURE(listen(get_socket(localhost), SOCK_BACKLOG))) {
        printf("\nError: listen() failed with errno %d: %s\n", errno, strerror(errno));
        return ERROR;
    }

    while(is_communicating(localhost)) 
    {
        remotehost = create_host("", 0000);
        if (remotehost == NULL) {
            fprintf(stderr, "\nFatal error.\n");
            goto early_exit;
        }
        er = RECV_TRYAGAIN;
        while (er == RECV_TRYAGAIN) {
            er =
            try_accept_connection (localhost, remotehost);
        }
        if (er == RECV_ERROR) {
            destroy_host(&remotehost);
            continue;
        }
        if (packet_receiver_type == PACKET_RECEIVER_TLS) {
            if(FAILURE(attempt_tls_handshake (remotehost, ssl_context))) {;
                perror("\nError: TLS Handshake failed.\n");
                destroy_host(&remotehost);
                continue;
            }
        }

        reception_args = (struct packet_reception_args*)calloc(1, sizeof(struct packet_reception_args));
        if (reception_args == NULL) {
            goto early_exit;
        }
        // Remotehost pointer is now owned by new thread
        reception_args->remotehost     = remotehost;
        reception_args->localhost      = localhost;
        reception_args->packet_handler = packet_handler;
        reception_args->bytesToProcess = 0;
        reception_args->buffer         = (char*)calloc(PACKET_BUFFER_SIZE, sizeof(char));
        if (reception_args->buffer == NULL) {
            destroy_host (&remotehost);
            free        (reception_args);
            goto early_exit;
        }

        add_task_to_thread_pool(tcp_thread_pool, (void*)receive_tcp_packets, reception_args);
    }
early_exit: 
    destroy_thread_pool (&tcp_thread_pool);
    close_socket       (get_socket(localhost));
    SSL_CTX_free      (ssl_context);
    destroy_host       (&localhost);
    return SUCCESS;
}
static inline ssize_t recv_tcp_unencrypted(struct packet_reception_args *restrict args)
{
    ssize_t num_bytes = 0;
    num_bytes = recv(get_socket(args->remotehost), 
                     args->buffer, 
                     PACKET_BUFFER_SIZE, 
                     0);
    return num_bytes;
}
static inline ssize_t recv_tcp_encrypted(struct packet_reception_args *restrict args)
{
    ssize_t num_bytes = 0;
    num_bytes = SSL_read(get_host_ssl(args->remotehost), 
                        args->buffer, 
                        PACKET_BUFFER_SIZE);
    return num_bytes;
}

void receive_tcp_packets(struct packet_reception_args *args) 
{
#ifdef DEBUG
    fprintf(stderr, "\nReceiving a TCP packet in a thread...");
#endif
    ssize_t num_bytes = 0;
    
    while(is_communicating(args->remotehost)) {
        // This is supposed to block until bytes are received
        num_bytes = recv_variants[packet_receiver_type](args);
        if (num_bytes >= 0) {
            args->packet_handler(args->buffer, num_bytes, args->remotehost); 
            if (num_bytes == 0) {
                fprintf(stderr, "\nConnection shutdown triggered by recv()...");
                close_connections(args->remotehost);
            }
        }
        else {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                continue;
            }
            fprintf(stderr, "\nSocket error, closing connection...\n");
            close_connections(args->remotehost);
        }
    }
    // Let the remote host know we're closing connection
    send_data_tcp                (NULL, 0, args->remotehost);
    close_socket                (get_socket(args->remotehost));
    destroy_packet_reception_args (&args);
    return;
}

/*
 * Precondition that args pointer and members not NULL
 */
static void destroy_packet_reception_args(struct packet_reception_args **args)
{
    if (*args == NULL) {
        return;
    }
    destroy_host (&(*args)->remotehost); 
    free        ((*args)->buffer);
    free        (*args);
    *args = NULL;
}
