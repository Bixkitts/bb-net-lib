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

BBNETAPI int listenForUDP(Host *localhost, 
                          void (*packet_handler)(char*, ssize_t, Host*));

BBNETAPI int listenForTCP(Host *localhost, 
                          void (*packet_handler)(char*, ssize_t, Host*));


void receiveTCPpackets   (packetReceptionArgs *args);

#endif
