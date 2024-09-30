#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "clientObject.h"
#include "listen.h"
#include "send.h"
#include "socketsNetLib.h"

#define SEND_LOCK_COUNT 32

enum packet_sender_type packet_sender_type = PACKET_SENDER_TCP;

typedef ssize_t (*packet_sender_t)(struct packet_sending_args *);
static inline ssize_t send_tcp_unencrypted(struct packet_sending_args *args);
static inline ssize_t send_tcp_encrypted(struct packet_sending_args *args);
static int wait_for_ready(int sockfd);
static packet_sender_t send_variants[PACKET_SENDER_COUNT] = {
    send_tcp_unencrypted,
    send_tcp_encrypted};

// We use these locks to make each TCP transfer on a socket a critical section
// and do it on multiple sockets simultaneously.
static pthread_mutex_t send_locks[SEND_LOCK_COUNT] = {
    PTHREAD_MUTEX_INITIALIZER};

void set_tcp_send_type(enum packet_sender_type type)
{
    packet_sender_type = type;
}

int send_data_udp(const char *data,
                  const ssize_t datasize,
                  struct host *remotehost)
{
#ifdef DEBUG
    fprintf(stderr, "\nSending UDP packet...");
#endif
    socketfd_t sockfd                     = get_socket(remotehost);
    socklen_t len                         = sizeof(remotehost->address);
    const struct sockaddr *remote_address = NULL;

    remote_address = (const struct sockaddr *)&remotehost->address;
    sendto(sockfd, data, datasize, MSG_CONFIRM, remote_address, len);

    return SUCCESS;
}

static inline ssize_t send_tcp_unencrypted(struct packet_sending_args *args)
{
    return send(get_socket(args->remotehost),
                args->buffer,
                args->bytesToProcess,
                0);
}
static inline ssize_t send_tcp_encrypted(struct packet_sending_args *args)
{
    return SSL_write(get_host_ssl(args->remotehost),
                     args->buffer,
                     args->bytesToProcess);
}
static int wait_for_ready(int sockfd)
{
    fd_set writefds;
    FD_ZERO(&writefds);
    FD_SET(sockfd, &writefds);

    int select_status = select(sockfd + 1, NULL, &writefds, NULL, NULL);
    if (select_status < 0) {
        perror("Select error");
        return -1;
    }
    return select_status > 0;
}
int send_data_tcp(const char *data,
                  const size_t datasize,
                  struct host *remotehost)
{
#ifdef DEBUG
    fprintf(stderr, "\nSending TCP packet...");
#endif
    int lock_index           = get_host_id(remotehost) % SEND_LOCK_COUNT;
    ssize_t total_bytes_sent = 0;
    ssize_t status           = 0;
    struct packet_sending_args send_args = {remotehost, data, datasize};
    pthread_mutex_lock(&send_locks[lock_index]);
    while (total_bytes_sent < datasize) {
        // A switch to send packets in different ways
        status = send_variants[packet_sender_type](&send_args);

        if (status == -1) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                if (wait_for_ready(get_socket(remotehost)) < 0) {
                    perror("\nSelect error");
                    close_connections(remotehost);
                    pthread_mutex_unlock(&send_locks[lock_index]);
                    return ERROR;
                }
                continue;
            }

            perror("\nFailed to send TCP message");
            close_connections(remotehost);
            pthread_mutex_unlock(&send_locks[lock_index]);
            return ERROR;
        }
        if (status == 0) {
            fprintf(stderr, "\nSocket is closed, couldn't send data");
            close_connections(remotehost);
            pthread_mutex_unlock(&send_locks[lock_index]);
            return SUCCESS;
        }
        total_bytes_sent += status;
    }
    pthread_mutex_unlock(&send_locks[lock_index]);
    return SUCCESS;
}

/*
 * TODO: Not currently working,
 * make it work.
 */
int send_data_tcp_and_recv(const char *data,
                           const ssize_t datasize,
                           struct host *remotehost,
                           void (*packet_handler)(char *,
                                                  ssize_t,
                                                  struct host *))
{
    struct packet_reception_args *recv_args = NULL;

    send_data_tcp(data, datasize, remotehost);

    recv_args = (struct packet_reception_args *)
        calloc(1, sizeof(struct packet_reception_args));
    if (recv_args == NULL) {
        close_connections(remotehost);
        return SEND_ERROR;
    }

    // Remotehost pointer is now owned by new thread
    recv_args->remotehost     = remotehost;
    recv_args->localhost      = NULL;
    recv_args->packet_handler = packet_handler;
    recv_args->bytesToProcess = 0;
    recv_args->buffer = (char *)calloc(PACKET_BUFFER_SIZE * 2, sizeof(char));
    if (recv_args->buffer == NULL) {
        free(recv_args);
        return SEND_ERROR;
    }

    receive_tcp_packets(recv_args);
    return SUCCESS;
}

/*
 * Returns the amount of bytes
 * sent, or -1 for an error OR -2
 * Call this function until it errors
 * or sends datasize bytes
 */
static ssize_t send_data_tcp_nb(const char *data,
                                const ssize_t datasize,
                                struct host *remotehost)
{
#ifdef DEBUG
    fprintf(stderr, "\nSending TCP packet...");
#endif
    int lock_index = get_host_id(remotehost) % SEND_LOCK_COUNT;
    ssize_t status = 0;
    struct packet_sending_args send_args = {remotehost, data, datasize};
    pthread_mutex_lock(&send_locks[lock_index]);
    // A switch to send packets in different ways
    status = send_variants[packet_sender_type](&send_args);

    if (status == -1) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return SEND_TRYAGAIN;
        }
        perror("\nFailed to send TCP message");
        close_connections(remotehost);
        pthread_mutex_unlock(&send_locks[lock_index]);
        return SEND_ERROR;
    }
    if (status == 0) {
        fprintf(stderr, "\nSocket is closed, couldn't send data");
        close_connections(remotehost);
        pthread_mutex_unlock(&send_locks[lock_index]);
        return SUCCESS;
    }
    pthread_mutex_unlock(&send_locks[lock_index]);
    return status;
}

int multicast_tcp(const char *data, const ssize_t datasize, int cacheIndex)
{
#ifdef DEBUG
    fprintf(stderr, "\nMulticasting to cache number %d...", cacheIndex);
#endif
    struct host *remotehost               = NULL;
    bool try_again                        = 1;
    ssize_t current_status                = 0;
    ssize_t statuses[MAX_HOSTS_PER_CACHE] = {0};

    for (int i = 0; i < MAX_HOSTS_PER_CACHE; i++) {
        statuses[i] = SEND_TRYAGAIN;
    }
    while (try_again == true) {
        try_again = false;
        for (int i = 0; i < MAX_HOSTS_PER_CACHE; i++) {
            remotehost = get_host_from_cache(cacheIndex, i);
            if (remotehost == NULL) {
                continue;
            }
            current_status = statuses[i];
            if ((current_status < datasize && current_status > 0) ||
                current_status == SEND_TRYAGAIN) {
                current_status = send_data_tcp_nb(data, datasize, remotehost);
                try_again = (current_status < datasize && current_status > 0 &&
                             try_again == 0) ||
                            current_status == SEND_TRYAGAIN;
            }
        }
    }
    return SUCCESS;
}

int connect_to_tcp(struct host *remotehost)
{
    const socketfd_t sockfd         = create_socket(SOCK_DEFAULT_TCP);
    struct sockaddr *remote_address = (struct sockaddr *)&remotehost->address;
    const socklen_t size_of_address = sizeof(remotehost->address);
    if (FAILURE(connect(sockfd, remote_address, size_of_address))) {
        perror("\nConnect failed");
        return ERROR;
    }
    set_socket(remotehost, sockfd);
    return SUCCESS;
}
