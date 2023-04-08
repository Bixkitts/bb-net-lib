#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <strings.h>
#include <unistd.h>
#include <limits.h>
#include <errno.h>

#include "defines.h"
#include "clientObject.h"
#include "socketsNetLib.h"

socketfd createSocket(socketfd value)             
{
    socketfd sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if ( IS_INVALID_FD(socket) )
    { 
        perror("socket creation failed"); 
        return ERROR;
    }   
    return sockfd;
}

void closeSocket(socketfd sockfd)
{
    close(sockfd);
}

int bindSocket(socketfd sockfd, Client* localhost)
{
    struct sockaddr* boundAddress = ( struct sockaddr *)&localhost->address;
    if(FAILURE(bind(sockfd, boundAddress, sizeof(localhost->address))))
    {
        perror("Failed to bind socket!");
        return ERROR;
    }
    return SUCCESS;
}
