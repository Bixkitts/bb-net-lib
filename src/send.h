#ifndef NETLIB_SEND
#define NETLIB_SEND

#include "clientObject.h"

typedef struct {
    Host       *remotehost;
    const char *buffer;
    ssize_t     bytesToProcess;
} PacketSendingArgs;

typedef enum {
    PACKET_SENDER_TCP,
    PACKET_SENDER_TLS,
    PACKET_SENDER_COUNT
}PacketSenderType;

BBNETAPI int sendDataUDP  (const char *data, 
                           const ssize_t datasize, 
                           Host *remotehost);
BBNETAPI int sendDataTCP  (const char *data, 
                           const size_t datasize, 
                           Host *remotehost);
BBNETAPI int connectToTCP (Host *remotehost);


void setTCP_sendType (PacketSenderType type);

#endif
