#ifndef LISTEN
#define LISTEN

#include <stdbool.h>
#include "clientObject.h"
#include "defines.h"

BBNETAPI int listenForUDP(Host *localhost, 
                          void (*packet_handler)(char*, ssize_t, Host*));

BBNETAPI int listenForTCP(Host *localhost, 
                          void (*packet_handler)(char*, ssize_t, Host*));

#endif
