#include <stdio.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <strings.h>
#include <unistd.h>
#include <fcntl.h>

#include "defines.h"
#include "clientObject.h"
#include "socketsNetLib.h"

socketfd createSocket(socketfd value)             
{
    socketfd sockfd = value;
    if (IS_INVALID_FD(socket)) { 
        perror("\nSocket creation failed"); 
        return ERROR;
    }   
    return sockfd;
}

void closeSocket(socketfd sockfd)
{
    close(sockfd);
}

int bindSocket(socketfd sockfd, Host* localhost)
{
    struct sockaddr* boundAddress = ( struct sockaddr *)&localhost->address;
    if(FAILURE(bind(sockfd, 
                    boundAddress, 
                    sizeof(localhost->address)))) {
        perror("\nFailed to bind socket!");
        return ERROR;
    }
    return SUCCESS;
}
int setSocketNonBlock(socketfd sockfd)
{    
    int flags = fcntl(sockfd, F_GETFL, 0);
    if (flags == -1) {
        return ERROR;
    }
    if (fcntl(sockfd, F_SETFL, flags | O_NONBLOCK) == -1) {
        perror("Error setting socket to non-blocking mode");
        return ERROR;
    }
    return SUCCESS; 
}
