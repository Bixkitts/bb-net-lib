#include <netinet/in.h>
#include <pthread.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <strings.h>
#include <unistd.h>
#include <string.h>

#include "clientObject.h"

Host* createHost(const char *ip, const uint16_t port)
{
    Host* host = NULL;

    host = (struct Host*)calloc(1, sizeof(struct Host));
    if (host == NULL) {
        perror(errStrings[STR_ERROR_MALLOC]);
        return NULL;
    }
    //filling in the data of the host's ip.
    strcpy((char*)host->addressStr, ip);
    host->address.sin_family = AF_INET;
    host->address.sin_port   = htons(port);

    inet_pton            (AF_INET, ip, &host->address.sin_addr);
    setHostPacketHandler (host, NULL);

    return host;
}

void copyHost(Host* dstHost, Host* srcHost)
{
    memcpy(dstHost, srcHost, sizeof(Host));
}
const char* getIP(Host* host)
{
    return (const char*)host->addressStr;
}
uint16_t getPort(Host* host)
{
    return ntohs(host->address.sin_port);
}
void destroyHost(Host** host)
{
    if (*host != NULL) {
        free(*host);
        *host = NULL;
    }
}

void closeConnections(Host* host)
{
    // Should be fine without mutex lock,
    // is volatile and will only ever
    // be UNSET asyncronously to break
    // out of a loop, and not set.
    host->bListen = 0;
}

void setCommunicating(Host* host)
{
    host->bListen = 1;
}

bool isCommunicating(const Host* host)
{
    return host->bListen;
}

void setSocket(Host* host, socketfd sockfd)
{
    host->associatedSocket = sockfd;
}

socketfd getSocket(const Host* host)
{
    return host->associatedSocket;
}

void callHostPacketHandler(char* data, uint16_t size, Host* host)
{
    (*host->packet_handler)(data, size, host);
}

void setHostPacketHandler(Host* host, void (*packet_handler)(char*, uint16_t, Host*))
{
    host->packet_handler = packet_handler;
}

void (*getHostPacketHandler(Host* host))(char*, uint16_t, Host*)
{
    return host->packet_handler;
}
