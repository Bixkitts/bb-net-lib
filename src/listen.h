#ifndef LISTEN
#define LISTEN

#include "clientObject.h"
#include "defines.h"
#include "threadPool.h"
#include <stdbool.h>

#define RECV_ERROR    -1
#define RECV_TRYAGAIN -2
extern struct thread_pool *tcp_thread_pool;
extern struct thread_pool *udp_thread_pool;

struct packet_reception_args {
    struct host *localhost;
    struct host *remotehost;
    char *buffer;
    ssize_t bytesToProcess;
    void (*packet_handler)(char *, ssize_t, struct host *);
};

enum packet_receiver_type {
    PACKET_RECEIVER_TCP,
    PACKET_RECEIVER_TLS,
    PACKET_RECEIVER_COUNT
};

BBNETAPI int listen_for_udp(struct host *localhost,
                            void (*packet_handler)(char *,
                                                   ssize_t,
                                                   struct host *));

BBNETAPI int listen_for_tcp(struct host *localhost,
                            void (*packet_handler)(char *,
                                                   ssize_t,
                                                   struct host *));

void set_tcp_receive_type(enum packet_receiver_type);

void receive_tcp_packets(struct packet_reception_args *args);
void receive_tls_packets(struct packet_reception_args *args);

#endif
