#include <sys/types.h>
#include <sys/socket.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <strings.h>
#include <unistd.h>
#include <stdio.h>

#include "clientObject.h"
#include "socketsNetLib.h"

int sendDataUDP(const char *data, const uint16_t datasize, Client *remotehost)
{
    socketfd sockfd;
    if(IS_INVALID_FD(getSocket(remotehost)))
    {
       sockfd = createSocket(SOCK_DEFAULT_UDP); 
       setSocket(remotehost, sockfd);
    }else
    {
        sockfd = getSocket(remotehost);
    }
    socklen_t len = sizeof(remotehost->address);    
    const struct sockaddr* remoteAddress = 
        (const struct sockaddr *) &remotehost->address; 
    // no error checking
    sendto(sockfd, data, datasize, MSG_CONFIRM, remoteAddress, len);
    
    return SUCCESS;
}

int sendDataTCP(const char *data, const uint16_t datasize, const Client *remotehost)
{
    if (FAILURE(send(getSocket(remotehost), data, datasize, 0))) 
    {
        perror("Failed to send TCP message\n");
        return ERROR;
    }
    return SUCCESS;
}

int connectToTCP(Client *remotehost)
{
    socketfd sockfd;
    
    struct sockaddr* remoteAddress = 
        (struct sockaddr *)&remotehost->address.sin_addr;
    int sizeOfAddress = sizeof(remotehost->address.sin_addr);

    if (IS_INVALID_FD(connect(sockfd, remoteAddress, sizeOfAddress)))
    {
        perror("connect failed");
        return ERROR;
    }
    setSocket(remotehost, sockfd);
    return SUCCESS;
}
