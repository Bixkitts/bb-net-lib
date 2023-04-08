#ifndef LISTEN
#define LISTEN

#include <stdbool.h>
#include "clientObject.h"
#include "defines.h"

BBNETAPI int listenForUDP(char *buffer, uint16_t bufsize, Client *localhost, Client *remotehost);

BBNETAPI int listenForTCP(char *buffer, uint16_t bufsize, Client *localhost, const Client *remotehost);
BBNETAPI int receiveTCPpackets(char *buffer, uint16_t bufsize, const Client *localhost) ;

static int bindSocket(const socketfd sockfd, const Client *client);


#endif
