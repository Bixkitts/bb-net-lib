#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <strings.h>
#include <unistd.h>
#include <stdio.h>

#include "clientObject.h"
#include "socketsNetLib.h"

int sendDataUDP(const char *data, const uint16_t datasize, const Client *remotehost)
{
    socklen_t len = sizeof(remotehost->address);    
    
    // no error checking
    sendto(sockfd, data, datasize, MSG_CONFIRM, 
        (const struct sockaddr *) &remotehost->address, len);
    
    return 0;
}

int sendDataTCP(const char *data, const uint16_t datasize, const socketfd sockfd)
{
    if (send(sockfd, data, datasize, 0) < 0) 
    {
        perror("Failed to send TCP message\n");
        return -1;
    }
    return 0;
}

int connectToTCP(const socketfd sockfd, const Client *remotehost)
{
    if (connect(sockfd, (struct sockaddr *)&remotehost->address.sin_addr, sizeof(remotehost->address.sin_addr)) < 0)
    {
        perror("connect failed");
        return -1;
    }
    return 0;
}
