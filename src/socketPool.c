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
#include "socketPool.h"


static socketfd socketPool[SOCK_MAX];        // A pool to get sockets from
static char socketLUT[SOCK_MAX/8];           // LUT for a free spot to


socketfd createSocket()             
{
    socketfd sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if ( INVALID_FD(sockfd) )
    { 
        perror("socket creation failed"); 
        return ERROR;
    }   
    return sockfd;
}