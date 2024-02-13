#ifndef NETLIB_SEND
#define NETLIB_SEND

#include <stdint.h>
#include "clientObject.h"

BBNETAPI int sendDataUDP  (const char *data, 
                           const uint16_t datasize, 
                           Host *remotehost);
BBNETAPI int sendDataTCP  (const char *data, 
                           const uint64_t datasize, 
                           Host *remotehost);
BBNETAPI int connectToTCP (Host *remotehost);

#endif
