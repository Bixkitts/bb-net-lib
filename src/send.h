#ifndef NETLIB_SEND
#define NETLIB_SEND

#include "clientObject.h"

BBNETAPI int sendDataUDP(const char *data, const uint16_t datasize, Client *remotehost);
BBNETAPI int sendDataTCP(const char *data, const uint16_t datasize, const Client *remotehost);
BBNETAPI int connectToTCP(Client *remotehost);

#endif
