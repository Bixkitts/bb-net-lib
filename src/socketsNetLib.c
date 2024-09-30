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

socketfd_t createSocket(socketfd_t value)             
{
    socketfd_t sockfd = value;
    if (IS_INVALID_FD(socket)) { 
        perror("\nSocket creation failed"); 
        return ERROR;
    }   
    return sockfd;
}

void closeSocket(socketfd_t sockfd)
{
    close(sockfd);
}

int bindSocket(socketfd_t sockfd, struct host* localhost)
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
int setSocketNonBlock(socketfd_t sockfd)
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
/*
 * This only works for blocking sockets,
 * don't use.
 */
int setSocketTimeout(socketfd_t sockfd, long secs)
{
    struct timeval timeout = {};
    timeout.tv_sec  = secs;   // 5 seconds
    timeout.tv_usec = 0;  // 0 microseconds
    if (FAILURE(setsockopt(sockfd, 
                           SOL_SOCKET, 
                           SO_RCVTIMEO, 
                           (char *)&timeout, sizeof(timeout)))) 
    {
        perror("\nSetsockopt error");
    }
    if (FAILURE(setsockopt(sockfd, 
                           SOL_SOCKET, 
                           SO_SNDTIMEO, 
                           (char *)&timeout, sizeof(timeout)))) 
    {
        perror("\nSetsockopt error");
    }

    return 0;
}
