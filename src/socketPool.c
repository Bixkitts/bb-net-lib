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
static u_char socketLUT[SOCK_MAX/8];           // LUT for a free spot to

socketIndex createSocket()             
{
    int index;
    if(FAILURE(findFreeSocket(&index)))
    {
        perror("failure to find a free socket!");
        return ERROR;
    }
    socketfd sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if ( INVALID_FD(sockfd) )
    { 
        perror("socket creation failed"); 
        return ERROR;
    }   
    socketPool[index] = sockfd;
    return index;
}

socketfd socketAtIndex(socketIndex index)
{

}

static int findFreeSocket(int* index)
{
    int i, j;
    for (i = 0; i < SOCK_MAX; i++) 
    {
        if (socketLUT[i] == 0xff) 
        {
            continue;  // all bits are set, check next byte
        }
        for (j = 0; j < 8; j++) 
        {
            if (!(socketLUT[i] & (1 << j))) 
            {
                *index = i * 8 + j;  // found 0 bit, return its position
            }
        }
    }
    return ERROR;  // no 0 bit found
}
