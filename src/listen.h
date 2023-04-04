#ifndef LISTEN
#define LISTEN

#include <stdbool.h>
#include "clientObject.h"

int listenForUDP(char *buffer, uint16_t bufsize, Client *localhost, Client *remotehost);

int listenForTCP(char *buffer, uint16_t bufsize, const socketfd sockfd, Client *localhost, const Client *remotehost);
int receiveTCPpackets(char *buffer, uint16_t bufsize, const socketfd sockfd, const Client *localhost) ;

static int bindSocket(const socketfd sockfd, const Client *client);


#endif