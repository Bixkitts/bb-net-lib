#ifndef LISTEN
#define LISTEN

#include <stdbool.h>
#include "clientObject.h"
#include "defines.h"
#include "threadPool.h"

extern threadPool TCPthreadPool;
extern threadPool UDPthreadPool;

BBNETAPI int listenForUDP(Host *localhost, 
                          void (*packet_handler)(char*, ssize_t, Host*));

BBNETAPI int listenForTCP(Host *localhost, 
                          void (*packet_handler)(char*, ssize_t, Host*));

#endif
