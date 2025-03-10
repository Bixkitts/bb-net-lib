#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <malloc.h>
#include <netdb.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "clientObject.h"
#include "defines.h"
#include "encryption.h"
#include "listen.h"
#include "send.h"
#include "socketsNetLib.h"
#include "threadPool.h"

struct thread_pool *tcp_thread_pool = NULL;
struct thread_pool *udp_thread_pool = NULL;

// global sslContext TCP... move this?
static SSL_CTX *ssl_context = NULL;

static void sigpipe_ignorer();

// Global switch for what type of TCP recv() we'll be doing
static enum packet_receiver_type packet_receiver_type = PACKET_RECEIVER_TCP;

typedef ssize_t (*packet_receiver_t)(struct packet_reception_args *);

static inline ssize_t
recv_tcp_unencrypted(struct packet_reception_args *restrict args);
static inline ssize_t
recv_tcp_encrypted(struct packet_reception_args *restrict args);
static packet_receiver_t recv_variants[PACKET_RECEIVER_COUNT] = {
    recv_tcp_unencrypted,
    recv_tcp_encrypted};

// TODO: Move these to their own file
// and have a special allocator
static void destroy_packet_reception_args(struct packet_reception_args **args);
static struct packet_reception_args
*create_packet_reception_args(struct host *localhost,
                              struct host *remotehost,
                              void (*packet_handler)(char *,
                                                     ssize_t,
                                                     struct host *));

void set_tcp_receive_type(enum packet_receiver_type type)
{
    packet_receiver_type = type;
}

int listen_for_udp(struct host *localhost,
                   void (*packet_handler)(char *,
                                          ssize_t,
                                          struct host
                                              *)) // Should be called on it's
                                                  // own thread as the while
                                                  // loop is blocking
{
    const socketfd_t sockfd         = create_socket(SOCK_DEFAULT_UDP);
    struct host remotehost          = {0};
    ssize_t num_bytes               = 0;
    socklen_t len                   = 0;
    char buffer[PACKET_BUFFER_SIZE] = {0};

    if (FAILURE(bind_socket(sockfd, localhost))) {
        perror("Failed to listen for UDP \n");
        return ERROR;
    }

    set_communicating(localhost);
    set_communicating(&remotehost);

    len = sizeof(localhost->address);
    // Need to cast the pointer to a sockaddr type to satisfy the syscall
    struct sockaddr *remote_address = (struct sockaddr *)&remotehost.address;

    while (is_communicating(localhost)) {
        num_bytes = recvfrom(sockfd,
                             buffer,
                             PACKET_BUFFER_SIZE,
                             MSG_WAITALL,
                             remote_address,
                             &len);

        if (num_bytes < PACKET_BUFFER_SIZE) {
            buffer[num_bytes] = '\0'; // Null terminate the received data
        }

        if (num_bytes == 0) {
            printf("Transmission finished\n");
            break;
        }
        // TODO: this is currently blocking and should run in it's own thread
        // from the pool, but I don't need UDP right now and even if I did it
        // should be _okay_ for a small amount of hosts.
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

static int try_accept_connection(struct host *localhost,
                                 struct host *remotehost)
{
    struct sockaddr *remote_address = (struct sockaddr *)&remotehost->address;
    socklen_t        addr_len       = sizeof(remotehost->address);
    socketfd_t       sockfd;

    sockfd = accept(get_socket(localhost), remote_address, &addr_len);
    if (sockfd == -1) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return RECV_TRYAGAIN; // No connection ready, try again later
        } else {
            perror("accept");
            return RECV_ERROR;
        }
    }
    if (set_socket_non_block(sockfd) == -1) {
        close(sockfd);
        return RECV_ERROR;
    }
    set_socket(remotehost, sockfd);
    set_communicating(remotehost);

    return 0;
}

static void sigpipe_ignorer()
{
    static sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGPIPE);
    if (pthread_sigmask(SIG_BLOCK, &set, NULL) != 0) {
        fprintf(stderr, "\nError setting SIGPIPE signal mask. Exiting...\n");
        exit(1);
    }
}

static void set_up_tls()
{
    if (packet_receiver_type == PACKET_RECEIVER_TLS) {
        ssl_context = create_ssl_context();
        configure_ssl_context(ssl_context);
    }
}

static struct packet_reception_args
*create_packet_reception_args(struct host *localhost,
                              struct host *remotehost,
                              void (*packet_handler)(char *,
                                                     ssize_t,
                                                     struct host *))
{
    // TODO: custom allocator, calloc here sucks
    struct packet_reception_args *reception_args = NULL;
    reception_args = calloc(1, sizeof(*reception_args));
    if (!reception_args) {
        return NULL;
    }
    reception_args->remotehost     = remotehost;
    reception_args->localhost      = localhost;
    reception_args->packet_handler = packet_handler;
    reception_args->bytesToProcess = 0;
    reception_args->buffer = calloc(PACKET_BUFFER_SIZE, sizeof(char));
    if (!reception_args->buffer) {
        destroy_host(&remotehost);
        free(reception_args);
        return NULL;
    }
    return reception_args;
}

static void packet_handle_in_new_thread(struct host *localhost,
                                        struct host *remotehost,
                                        void (*packet_handler)(char *,
                                                               ssize_t, 
                                                               struct host *))
{
    struct packet_reception_args
        *reception_args = create_packet_reception_args(localhost,
                                                       remotehost,
                                                       packet_handler);
    add_task_to_thread_pool(tcp_thread_pool,
                            (void *)receive_tcp_packets,
                            reception_args);
}

static void proc_epolled_tcp_socks(struct host *localhost,
                                   struct socket_epoller *localhost_poller,
                                   int num_incoming_conn,
                                   void (*packet_handler)(char *, ssize_t, struct host *))
{
    int er = 0;
    for (int i = 0; i < num_incoming_conn; i++) {
        struct host *host_with_socket_activity =
            (struct host *)localhost_poller->events[i].data.ptr;
        struct host *remotehost = create_host("", 0000);
        if (!remotehost) {
            fprintf(stderr, "\nFatal error.\n");
            break;
        }
        er = try_accept_connection(localhost, remotehost);
        if (er) {
            destroy_host(&remotehost);
            break;
        }
        if (packet_receiver_type == PACKET_RECEIVER_TLS) {
            if (FAILURE(attempt_tls_handshake(remotehost, ssl_context))) {
                perror("\nError: TLS Handshake failed.\n");
                destroy_host(&remotehost);
                break;
            }
        }
        packet_handle_in_new_thread(localhost,
                                    remotehost,
                                    packet_handler);
    }
}

static void tcp_accept_loop(struct host *localhost,
                            struct socket_epoller *epoller,
                            void (*packet_handler)(char *, ssize_t, struct host *))
{
    while (is_communicating(localhost)) {
        int n = epoll_wait(epoller->epoll_fd, epoller->events, MAX_EPOLL_EVENTS, -1);
        if (n == -1) {
            perror("epoll_wait");
            break;
        }
        proc_epolled_tcp_socks(localhost,
                               epoller,
                               n,
                               packet_handler);
    }
}

/*
 * Core TCP listening function.
 * Call it once and it will block
 * and listen until the localhost
 * is set not to listen any more.
 * */
int listen_for_tcp(struct host *localhost,
                   void (*packet_handler)(char *, ssize_t, struct host *))
{
    debug_print("\nListening for TCP connections...\n");
    struct socket_epoller         epoller        ={0};

    sigpipe_ignorer();
    tcp_thread_pool = create_thread_pool();
    if (!tcp_thread_pool) {
        return ERROR;
    }
    set_socket(localhost, create_socket(SOCK_DEFAULT_TCP));
    set_socket_non_block(get_socket(localhost));

    set_up_tls();

    init_socket_poller(&epoller);
    add_socket_to_epoll(localhost, &epoller);

    if (FAILURE(bind_socket(get_socket(localhost), localhost))) {
        perror("Failed to listen for TCP\n");
        return ERROR;
    }
    set_communicating(localhost);
    if (FAILURE(listen(get_socket(localhost), SOCK_BACKLOG))) {
        printf("\nError: listen() failed with errno %d: %s\n",
               errno,
               strerror(errno));
        return ERROR;
    }

    tcp_accept_loop(localhost, &epoller, packet_handler);

    destroy_thread_pool(&tcp_thread_pool);
    destroy_socket_poller(&epoller);
    close_socket(get_socket(localhost));
    SSL_CTX_free(ssl_context);
    destroy_host(&localhost);
    return SUCCESS;
}

static inline ssize_t
recv_tcp_unencrypted(struct packet_reception_args *restrict args)
{
    ssize_t num_bytes = 0;
    num_bytes =
        recv(get_socket(args->remotehost), args->buffer, PACKET_BUFFER_SIZE, 0);
    return num_bytes;
}
static inline ssize_t
recv_tcp_encrypted(struct packet_reception_args *restrict args)
{
    ssize_t num_bytes = 0;
    num_bytes         = SSL_read(get_host_ssl(args->remotehost),
                         args->buffer,
                         PACKET_BUFFER_SIZE);
    return num_bytes;
}

/* will always be ran in it's own thread,
 * and is responsible for cleaning up args */
void receive_tcp_packets(struct packet_reception_args *args)
{
    debug_print("Receiving TCP packets in a thread...\n");
    ssize_t num_bytes = 0;
    // TODO: we could actually handle multiple
    // sockets per thread instead of a fresh
    // thread for each socket!
    struct socket_epoller remotehost_poller = {};

    init_socket_poller(&remotehost_poller);
    add_socket_to_epoll(args->remotehost, &remotehost_poller);
    while (is_communicating(args->remotehost)) {
        int n = epoll_wait(remotehost_poller.epoll_fd, remotehost_poller.events, MAX_EPOLL_EVENTS, -1);
        if (n == -1) {
            perror("epoll_wait");
            close_connections(args->remotehost);
        }
        for (int i = 0; i < n; i++) {
            struct host *host_with_socket_activity = (struct host *)remotehost_poller.events[i].data.ptr;
            num_bytes = recv_variants[packet_receiver_type](args);
            if (num_bytes >= 0) {
                args->packet_handler(args->buffer, num_bytes, args->remotehost);
                if (num_bytes == 0) {
                    fprintf(stderr, "Connection shutdown triggered by recv()...\n");
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
    }
    send_data_tcp(NULL, 0, args->remotehost);
    close_socket(get_socket(args->remotehost));
    destroy_packet_reception_args(&args);
    destroy_socket_poller(&remotehost_poller);
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
    destroy_host(&(*args)->remotehost);
    free((*args)->buffer);
    free(*args);
    *args = NULL;
}
