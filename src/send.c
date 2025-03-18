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

enum packet_sender_type packet_sender_type = PACKET_SENDER_TCP;

typedef ssize_t (*packet_sender_t)(struct packet_sending_args *);
static inline ssize_t send_tcp_unencrypted(struct packet_sending_args *args);
static inline ssize_t send_tcp_encrypted(struct packet_sending_args *args);
static int wait_for_ready(int sockfd);
static packet_sender_t send_variants[PACKET_SENDER_COUNT] = {
    send_tcp_unencrypted,
    send_tcp_encrypted};

void set_tcp_send_type(enum packet_sender_type type)
{
    packet_sender_type = type;
}

int send_data_udp(const char *data,
                  const ssize_t datasize,
                  struct host *remotehost)
{
    debug_print("Seding UDP packet...\n");
    socketfd_t sockfd = get_socket(remotehost);
    const struct sockaddr *remote_address =
        (const struct sockaddr *)get_host_addr(remotehost);
    sendto(sockfd,
           data,
           datasize,
           MSG_CONFIRM,
           remote_address,
           sizeof(*remote_address));

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
    debug_print("Sending TCP packet...\n");
    size_t total_bytes_sent = 0;
    int    status           = 0;
    struct packet_sending_args send_args = {remotehost, data, datasize};
    while (total_bytes_sent < datasize) {
        // A switch to send packets in different ways
        status = send_variants[packet_sender_type](&send_args);
        if (status == -1) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                if (wait_for_ready(get_socket(remotehost)) < 0) {
                    perror("Select error\n");
                    close_connections(remotehost);
                    return ERROR;
                }
                continue;
            }

            perror("Failed to send TCP message\n");
            close_connections(remotehost);
            return ERROR;
        }
        if (status == 0) {
            fprintf(stderr, "Socket is closed, couldn't send data\n");
            close_connections(remotehost);
            return SUCCESS;
        }
        total_bytes_sent += status;
    }
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
    debug_print("Sending TCP packet...\n");
    ssize_t status = 0;
    struct packet_sending_args send_args = {remotehost, data, datasize};
    // A switch to send packets in different ways
    status = send_variants[packet_sender_type](&send_args);

    if (status == -1) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return SEND_TRYAGAIN;
        }
        perror("Failed to send TCP message\n");
        close_connections(remotehost);
        return SEND_ERROR;
    }
    if (status == 0) {
        fprintf(stderr, "Socket is closed, couldn't send data\n");
        close_connections(remotehost);
        return SUCCESS;
    }
    return status;
}

int multicast_tcp(const char *data, const ssize_t datasize, int cache_index)
{
    debug_print("Multicasting to cache number %d...", cache_index);
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
            remotehost = get_host_from_cache(cache_index, i);
            if (!remotehost) {
                continue;
            }
            current_status = statuses[i];
            if ((current_status < datasize && current_status > 0) ||
                current_status == SEND_TRYAGAIN) {
                current_status = send_data_tcp_nb(data, datasize, remotehost);
                try_again = (current_status < datasize
                             && current_status > 0
                             && try_again == 0)
                            || current_status == SEND_TRYAGAIN;
            }
        }
    }
    return SUCCESS;
}

int connect_to_tcp(struct host *remotehost)
{
    const socketfd_t sockfd = create_socket(SOCK_DEFAULT_TCP);
    const struct sockaddr *remote_address =
        (const struct sockaddr *)get_host_addr(remotehost);
    const socklen_t size_of_address = sizeof(*remote_address);
    if (FAILURE(connect(sockfd, remote_address, size_of_address))) {
        close(sockfd);
        perror("Connect failed\n");
        return ERROR;
    }
    set_socket(remotehost, sockfd);
    return SUCCESS;
}
