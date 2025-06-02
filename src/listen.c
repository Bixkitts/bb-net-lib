#include <assert.h>
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

static int sigpipe_ignorer(void);

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
    //    TODO: Reimplement this proper
//    struct host *remotehost = create_host("0.0.0.0",0);
//    ssize_t num_bytes       = 0;
//    char buffer[PACKET_BUFFER_SIZE] = {0};
//
//
//    set_communicating(localhost);
//    set_communicating(remotehost);
//
//    struct sockaddr *remote_address =
//        (struct sockaddr *)get_host_addr(remotehost);
//    socklen_t len = sizeof(remote_address);
//    while (is_communicating(localhost)) {
//        num_bytes = recvfrom(sockfd,
//                             buffer,
//                             PACKET_BUFFER_SIZE,
//                             MSG_WAITALL,
//                             remote_address,
//                             &len);
//
//        if (num_bytes < PACKET_BUFFER_SIZE) {
//            buffer[num_bytes] = '\0'; // Null terminate the received data
//        }
//
//        if (num_bytes == 0) {
//            printf("Transmission finished\n");
//            break;
//        }
//        // TODO: this is currently blocking and should run in it's own thread
//        // from the pool, but I don't need UDP right now and even if I did it
//        // should be _okay_ for a small amount of hosts.
//        packet_handler(buffer, num_bytes, remotehost);
//    }
//
//    if (is_communicating(localhost)) {
//        close_connections(localhost);
//    }
//    if (is_communicating(remotehost)) {
//        close_connections(remotehost);
//    }
//
//    return SUCCESS;
    return 0;
}

// Caller is expected to check return
// value and clean up remotehost
static int try_accept_connection(const struct host *localhost,
                                 struct host *remotehost)
{
    int er = host_accept(remotehost,
                         localhost);
    if (er) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return RECV_TRYAGAIN; // No connection ready, try again later
        }
        else {
            perror("accepting connection");
            return RECV_ERROR;
        }
    }
    if (set_host_non_blocking(remotehost) == -1) {
        return RECV_ERROR;
    }
    return 0;
}

static int sigpipe_ignorer(void)
{
    static sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGPIPE);
    if (0 != pthread_sigmask(SIG_BLOCK, &set, NULL)) {
        fprintf(stderr, "\nError setting SIGPIPE signal mask. Exiting...\n");
        return -1;
    }
    return 0;
}

// WARNING, WRITES GLOBAL VARIABLE ssl_context
// returns 0 on success
static int set_up_tls(void)
{
    if (packet_receiver_type != PACKET_RECEIVER_TLS) {
        return ERROR;
    }
    int er = 0;
    ssl_context = create_ssl_context();
    if (!ssl_context) return ERROR;
    er = configure_ssl_context(ssl_context);
    return er;
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
    if (!reception_args) {
        release_host(&remotehost);
        return;
    }
    add_task_to_thread_pool(tcp_thread_pool,
                            (void (*)(void *))receive_tcp_packets,
                            reception_args);
}

static void proc_epolled_tcp_socks(int num_incoming_conn,
                                   struct socket_epoller *epoller,
                                   void (*packet_handler)(char *, ssize_t, struct host *))
{
    int er = 0;
    for (int i = 0; i < num_incoming_conn; i++) {
        struct host *host_with_socket_activity =
            (struct host *)epoller->events[i].data.ptr;
        struct host *remotehost = create_host("", 0000);
        if (!remotehost) {
            fprintf(stderr, "\nFatal error creating host.\n");
            continue;
        }
        er = try_accept_connection(host_with_socket_activity, remotehost);
        if (er) {
            release_host(&remotehost);
            continue;
        }
        if (packet_receiver_type == PACKET_RECEIVER_TLS) {
            if (FAILURE(attempt_tls_handshake(remotehost, ssl_context))) {
                perror("TLS Handshake failed");
                release_host(&remotehost);
                continue;
            }
        }
        packet_handle_in_new_thread(host_with_socket_activity,
                                    remotehost,
                                    packet_handler);
    }
}

static void tcp_accept_loop(struct host *localhost,
                            struct socket_epoller *epoller,
                            void (*packet_handler)(char *, ssize_t, struct host *))
{
    while (is_host_listening(localhost)) {
        int number_of_sockets_ready = epoll_wait(epoller->epoll_fd,
                                                 epoller->events,
                                                 MAX_EPOLL_EVENTS,
                                                 -1);
        if (number_of_sockets_ready == -1) {
            perror("epoll_wait");
            break;
        }
        proc_epolled_tcp_socks(number_of_sockets_ready,
                               epoller,
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
    struct socket_epoller epoller = {0};
    int er = 0;

    er = sigpipe_ignorer();
    if (er) return ERROR;
    tcp_thread_pool = create_thread_pool();
    if (!tcp_thread_pool) return ERROR;

    er = create_host_tcp_socket_nb(localhost);
    if (er) goto cleanup_thread_pool;

    er = set_up_tls();
    if (er) goto cleanup_host;

    er = init_socket_epoller(&epoller);
    if (er) goto cleanup_ssl;

    er = add_host_socket_to_epoll(localhost, &epoller);
    if (er) goto cleanup_all;

    er = host_start_listening_tcp(localhost);
    if (er) goto cleanup_all;

    tcp_accept_loop(localhost, &epoller, packet_handler);

cleanup_all:
    destroy_socket_poller(&epoller);
cleanup_ssl:
    SSL_CTX_free(ssl_context);
cleanup_host:
    release_host(&localhost);
cleanup_thread_pool:
    destroy_thread_pool(&tcp_thread_pool);
    return er;
}

// TODO: why the indirection?
// Maybe just direct call
// --------------------------------------------
static inline ssize_t
recv_tcp_unencrypted(struct packet_reception_args *restrict args)
{
    return unencrypted_host_tcp_recv(args->remotehost, args->buffer, PACKET_BUFFER_SIZE);
}
static inline ssize_t
recv_tcp_encrypted(struct packet_reception_args *restrict args)
{
    return encrypted_host_tcp_recv(args->remotehost, args->buffer, PACKET_BUFFER_SIZE);
}
// --------------------------------------------

/* will always be ran in it's own thread,
 * and is responsible for cleaning up args */
void receive_tcp_packets(struct packet_reception_args *args)
{
    assert(args);
    debug_print("Receiving TCP packets in a thread...\n");
    int er = 0;
    // TODO: we could actually handle multiple
    // sockets per thread instead of a fresh
    // thread for each socket!
    // Every host gets it's own epoller for it's
    // file descriptor
    struct socket_epoller remotehost_poller = {0};

    er = init_socket_epoller(&remotehost_poller);
    if (er) goto cleanup_packet_rec_args;
    er = add_host_socket_to_epoll(args->remotehost,
                                  &remotehost_poller);
    if (er) goto cleanup_epoller;

    while (is_host_connected(args->remotehost)) {
        const int n = epoll_wait(remotehost_poller.epoll_fd,
                                 remotehost_poller.events,
                                 MAX_EPOLL_EVENTS,
                                 -1);
        if (-1 == n) {
            perror("epoll_wait");
            close_connection(args->remotehost);
        }
        for (int i = 0; i < n; i++) {
            const ssize_t num_bytes = recv_variants[packet_receiver_type](args);
            if (num_bytes >= 0) {
                args->packet_handler(args->buffer, num_bytes, args->remotehost);
                if (num_bytes == 0) {
                    fprintf(stderr, "Connection shutdown triggered by recv()...\n");
                    close_connection(args->remotehost);
                }
            }
            else {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    continue;
                }
                fprintf(stderr, "\nSocket error, closing connection...\n");
                close_connection(args->remotehost);
            }
        }
    }
    send_data_tcp(NULL, 0, args->remotehost);
cleanup_epoller:
    destroy_socket_poller(&remotehost_poller);
cleanup_packet_rec_args:
    destroy_packet_reception_args(&args);
    return;
}

static void destroy_packet_reception_args(struct packet_reception_args **args)
{
    assert(args);
    assert(*args);
    if (!(*args)) {
        return;
    }
    // We ONLY destroy the remote host
    // because the local host keeps listening
    release_host(&(*args)->remotehost);
    free((*args)->buffer);
    free(*args);
    *args = NULL;
}
