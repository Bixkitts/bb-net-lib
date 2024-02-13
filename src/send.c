#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <strings.h>
#include <unistd.h>
#include <stdio.h>

#include "clientObject.h"
#include "socketsNetLib.h"

int sendDataUDP(const char *data, const ssize_t datasize, Host *remotehost)
{
    socketfd  sockfd                     = getSocket(remotehost);
    socklen_t len                        = sizeof(remotehost->address);    
    const struct sockaddr* remoteAddress = NULL;

    remoteAddress = (const struct sockaddr *) &remotehost->address; 
    sendto (sockfd, data, datasize, MSG_CONFIRM, remoteAddress, len);
    
    return SUCCESS;
}

int sendDataTCP(const char *data, const ssize_t datasize, Host *remotehost)
{
    int status = send(getSocket(remotehost), data, datasize, 0);
    if (status == -1) {
        perror("Failed to send TCP message");
        closeConnections(remotehost);
        return ERROR;
    }
    if (status == 0) {
        perror("Connection closed by peer");
        closeConnections(remotehost);
    }
    return SUCCESS;
}

int connectToTCP(Host *remotehost)
{
    socketfd         sockfd        = 0;
    struct sockaddr* remoteAddress = (struct sockaddr *)&remotehost->address.sin_addr;
    unsigned int     sizeOfAddress = sizeof(remotehost->address.sin_addr);
    if (IS_INVALID_FD(connect(sockfd, remoteAddress, sizeOfAddress))) {
        perror("Connect failed");
        return ERROR;
    }
    setSocket(remotehost, sockfd);
    return SUCCESS;
}
