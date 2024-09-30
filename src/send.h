#ifndef NETLIB_SEND
#define NETLIB_SEND

#include "clientObject.h"

#define SEND_TRYAGAIN -2
#define SEND_ERROR    -1

struct packet_sending_args{
    struct host       *remotehost;
    const char *buffer;
    ssize_t     bytesToProcess;
};

enum packet_sender_type {
    PACKET_SENDER_TCP,
    PACKET_SENDER_TLS,
    PACKET_SENDER_COUNT
};

BBNETAPI int sendDataUDP  (const char *data, 
                           const ssize_t datasize, 
                           struct host *remotehost);
BBNETAPI int sendDataTCP  (const char *data, 
                           const size_t datasize, 
                           struct host *remotehost);
BBNETAPI int connectToTCP (struct host *remotehost);


void setTCP_sendType (enum packet_sender_type type);

#endif
