#ifndef LISTEN
#define LISTEN

#include <stdbool.h>
#include "clientObject.h"
#include "defines.h"
#include "threadPool.h"

extern threadPool TCPthreadPool;
extern threadPool UDPthreadPool;

typedef struct {
    Host       *localhost;
    Host       *remotehost;
    char       *buffer;
    ssize_t     bytesToProcess;
    void      (*packet_handler)(char*, ssize_t, Host*);
} packetReceptionArgs;

typedef enum {
    PACKET_RECEIVER_TCP,
    PACKET_RECEIVER_TLS,
    PACKET_RECEIVER_COUNT
}PacketReceiverType;

BBNETAPI int listenForUDP(Host *localhost, 
                          void (*packet_handler)(char*, ssize_t, Host*));

BBNETAPI int listenForTCP(Host *localhost, 
                          void (*packet_handler)(char*, ssize_t, Host*));

void setTCP_receiveType  (PacketReceiverType);

void receiveTCPpackets   (packetReceptionArgs *args);
void receiveTLSpackets   (packetReceptionArgs *args);

#endif
