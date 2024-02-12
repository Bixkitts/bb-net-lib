#ifndef LISTEN
#define LISTEN

#include <stdint.h>
#include <stdbool.h>
#include "clientObject.h"
#include "socketsNetLib.h"
#include "defines.h"

BBNETAPI int listenForUDP(Host *localhost, 
                          void (*packet_handler)(char*, int16_t, Host*));

BBNETAPI int listenForTCP(Host *localhost, 
                          void (*packet_handler)(char*, int16_t, Host*));

#endif
