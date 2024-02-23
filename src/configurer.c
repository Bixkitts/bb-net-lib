#include "configurer.h"
#include "listen.h"
#include "send.h"

void enableTLS()
{
    setTCP_receiveType(PACKET_RECEIVER_TLS); 
    setTCP_sendType   (PACKET_SENDER_TLS);
}
