#include <arpa/inet.h>
#include <assert.h>
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

enum packet_sender_type packet_sender_type = PACKET_SENDER_TCP;

typedef ssize_t (*packet_sender_t)(struct packet_sending_args *);
static inline ssize_t send_tcp_unencrypted(struct packet_sending_args *args);
static inline ssize_t send_tcp_encrypted(struct packet_sending_args *args);
static packet_sender_t tcp_send_functions[PACKET_SENDER_COUNT] = {
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
    //debug_print("Seding UDP packet...\n");
    //socketfd_t sockfd = get_socket(remotehost);
    //const struct sockaddr *remote_address =
    //    (const struct sockaddr *)get_host_addr(remotehost);
    //sendto(sockfd,
    //       data,
    //       datasize,
    //       MSG_CONFIRM,
    //       remote_address,
    //       sizeof(*remote_address));

    return -1;
}

static inline ssize_t send_tcp_unencrypted(struct packet_sending_args *args)
{
    return send_tcp_unencrypted_internal(args->remotehost,
                                         args->buffer,
                                         args->bytes_to_process);
}
static inline ssize_t send_tcp_encrypted(struct packet_sending_args *args)
{
    return send_tcp_encrypted_internal(args->remotehost,
                                       args->buffer,
                                       args->bytes_to_process);
}


/*
 * Virtually identical to send_data_tcp_nb,
 * but blocks by running in a loop until
 * transfer is complete
 */
int send_data_tcp(const char *data,
                  const size_t datasize,
                  struct host *remotehost)
{
    debug_print("Sending TCP packet...\n");
    size_t total_bytes_sent = 0;
    int    status           = 0;
    struct packet_sending_args send_args = {remotehost, data, datasize};
    while (total_bytes_sent < datasize) {
        status = tcp_send_functions[packet_sender_type](&send_args);
        if (0 == status) {
            fprintf(stderr, "Socket is closed, couldn't send data\n");
            close_connection(remotehost);
            return SUCCESS;
        }
        else if (-1 == status) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                if (host_socket_select(remotehost) < 0) {
                    perror("Select error\n");
                    close_connection(remotehost);
                    return ERROR;
                }
                continue;
            }

            perror("Failed to send TCP message\n");
            close_connection(remotehost);
            return ERROR;
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

    recv_args = calloc(1, sizeof(struct packet_reception_args));
    if (!recv_args) {
        close_connection(remotehost);
        return SEND_ERROR;
    }

    // Remotehost pointer is now owned by new thread
    recv_args->remotehost     = remotehost;
    recv_args->localhost      = NULL;
    recv_args->packet_handler = packet_handler;
    recv_args->bytesToProcess = 0;
    recv_args->buffer = calloc(PACKET_BUFFER_SIZE * 2, sizeof(char));
    if (!recv_args->buffer) {
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
 * --------------------------
 *  Virtually identical to send_data_tcp(), but
 *  returns instead of looping/blocking/selecting.
 *  This is static because it's only used
 *  by us internally for a round-robin multicast
 *  in multicast_tcp()
 */
ssize_t send_data_tcp_nb(const char *data,
                         const ssize_t datasize,
                         struct host *remotehost)
{
    debug_print("Sending TCP packet...\n");
    ssize_t status = 0;
    struct packet_sending_args send_args = {remotehost, data, datasize};
    status = tcp_send_functions[packet_sender_type](&send_args);
    if (0 == status) {
        fprintf(stderr, "Socket is closed, couldn't send data\n");
        close_connection(remotehost);
        return SUCCESS;
    }
    else if (-1 == status) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return SEND_TRYAGAIN;
        }
        perror("Failed to send TCP message\n");
        close_connection(remotehost);
        return SEND_ERROR;
    }
    return status;
}

int multicast_tcp(const char *data, const ssize_t datasize, int cache_index)
{
    assert(data && cache_index < MAX_HOST_CACHES);
    debug_print("Multicasting to cache number %d...", cache_index);
    int res = multicast_tcp_internal(data,
                                     datasize,
                                     cache_index,
                                     &send_data_tcp_nb);
    return res;
}

int connect_to_tcp(struct host *remotehost)
{
    return connect_to_tcp_internal(remotehost);
}
