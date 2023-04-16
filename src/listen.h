#ifndef LISTEN
#define LISTEN

#include <stdint.h>
#include <stdbool.h>
#include "clientObject.h"
#include "socketsNetLib.h"
#include "defines.h"

BBNETAPI int listenForUDP(char *buffer, const uint16_t bufsize, Client *localhost, Client *remotehost, void (*packet_handler)(char*, uint16_t, Client*));

BBNETAPI int listenForTCP(char *buffer, const uint16_t bufsize, Client *localhost, Client *remotehost, void (*packet_handler)(char*, uint16_t, Client*));

#endif
