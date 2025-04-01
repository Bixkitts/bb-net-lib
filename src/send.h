#ifndef NETLIB_SEND
#define NETLIB_SEND

#include "clientObject.h"

#define SEND_TRYAGAIN -2
#define SEND_ERROR    -1

struct packet_sending_args {
    struct host *remotehost;
    const char *buffer;
    ssize_t bytes_to_process;
};

enum packet_sender_type {
    PACKET_SENDER_TCP,
    PACKET_SENDER_TLS,
    PACKET_SENDER_COUNT
};

BBNETAPI int send_data_udp(const char *data,
                           const ssize_t datasize,
                           struct host *remotehost);
BBNETAPI int send_data_tcp(const char *data,
                           const size_t datasize,
                           struct host *remotehost);
BBNETAPI int connect_to_tcp(struct host *remotehost);

// Used exclusively by multicasting right now.
// TODO: expose non-blocking sending to client?
ssize_t send_data_tcp_nb(const char *data,
                         const ssize_t datasize,
                         struct host *remotehost);

void set_tcp_send_type(enum packet_sender_type type);

#endif
