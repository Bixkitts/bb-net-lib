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


static socketfd socketPool[SOCK_MAX] = {INVALID_FD};        // A pool to get sockets from

socketIndex createSocket()             
{
    socketIndex index;
    if(FAILURE(findFreeSocket(&index)))
    {
        perror("failure to find a free socket!");
        return ERROR;
    }
    socketPool[index] = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if ( IS_INVALID_FD(socketPool[index]) )
    { 
        perror("socket creation failed"); 
        return ERROR;
    }   
    return index;
}

socketfd getSocketAtIndex(socketIndex index)
{
    return socketPool[index];
}

void closeSocket(socketIndex index)
{
    close(socketPool[index]);
    socketPool[index] = INVALID_FD;
}

static int findFreeSocket(socketIndex* index)
{
    for (int i = 0; i < SOCK_MAX; i++) 
    {
        if(IS_INVALID_FD(socketPool[i]))
        {
            *index = i;
        }
    }
    return ERROR;  // No free Socket found!
}
