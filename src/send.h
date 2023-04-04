#ifndef SEND
#define SEND

#include "clientObject.h"

int sendDataUDP(const char *data, const uint16_t datasize, const socketfd sockfd, const Client *remotehost);
int sendDataTCP(const char *data, const uint16_t datasize, const socketfd sockfd);
int connectToTCP(const socketfd sockfd, const Client *remotehost);

#endif