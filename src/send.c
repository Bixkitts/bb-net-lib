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

int sendDataUDP(const char *data, const int16_t datasize, Host *remotehost)
{
    socketfd  sockfd                     = getSocket(remotehost);
    socklen_t len                        = sizeof(remotehost->address);    
    const struct sockaddr* remoteAddress = NULL;

    remoteAddress = (const struct sockaddr *) &remotehost->address; 
    sendto (sockfd, data, datasize, MSG_CONFIRM, remoteAddress, len);
    
    return SUCCESS;
}

int sendDataTCP(const char *data, const int64_t datasize, Host *remotehost)
{
    int status = send(getSocket(remotehost), data, datasize, 0);
    if (status == -1) 
    {
        perror("Failed to send TCP message\n");
        closeConnections(remotehost);
        return ERROR;
    }
    if (status == 0)
    {
        (void)printf("Connection closed by peer \n");
        closeConnections(remotehost);
    }
    return SUCCESS;
}

int connectToTCP(Host *remotehost)
{
    socketfd         sockfd        = 0;
    struct sockaddr* remoteAddress = (struct sockaddr *)&remotehost->address.sin_addr;
    int              sizeOfAddress = sizeof(remotehost->address.sin_addr);
    if (IS_INVALID_FD(connect(sockfd, remoteAddress, sizeOfAddress))) {
        perror("connect failed");
        return ERROR;
    }
    setSocket(remotehost, sockfd);
    return SUCCESS;
}
