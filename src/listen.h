#ifndef LISTEN
#define LISTEN

#include <stdbool.h>
#include "clientObject.h"
#include "defines.h"
#include "threadPool.h"

#define RECV_ERROR    -1
#define RECV_TRYAGAIN -2
extern struct thread_pool *TCPthreadPool;
extern struct thread_pool *UDPthreadPool;

struct packet_reception_args {
    struct host       *localhost;
    struct host       *remotehost;
    char       *buffer;
    ssize_t     bytesToProcess;
    void      (*packet_handler)(char*, ssize_t, struct host*);
};

enum packet_receiver_type {
    PACKET_RECEIVER_TCP,
    PACKET_RECEIVER_TLS,
    PACKET_RECEIVER_COUNT
};

BBNETAPI int listenForUDP(struct host *localhost, 
                          void (*packet_handler)(char*, ssize_t, struct host*));

BBNETAPI int listenForTCP(struct host *localhost, 
                          void (*packet_handler)(char*, ssize_t, struct host*));

void setTCP_receiveType  (enum packet_receiver_type);

void receiveTCPpackets   (struct packet_reception_args *args);
void receiveTLSpackets   (struct packet_reception_args *args);

#endif
