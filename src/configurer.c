#include "configurer.h"
#include "listen.h"
#include "send.h"

void enable_tls()
{
    set_tcp_receive_type(PACKET_RECEIVER_TLS);
    set_tcp_send_type(PACKET_SENDER_TLS);
}
