#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <strings.h>
#include <unistd.h>
#include <stdio.h>

#include "clientObject.h"
#include "socketsNetLib.h"

#define SEND_LOCK_COUNT 16

static pthread_mutex_t sendLocks[SEND_LOCK_COUNT]  = {PTHREAD_MUTEX_INITIALIZER};

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
    int lockIndex = getHostID(remotehost) % SEND_LOCK_COUNT;
    pthread_mutex_lock   (&sendLocks[lockIndex]);

    int status = send(getSocket(remotehost), data, datasize, 0);

    if (status == -1) {
        perror("Failed to send TCP message");
        closeConnections     (remotehost);
        pthread_mutex_unlock (&sendLocks[lockIndex]);
        return ERROR;
    }
    if (status == 0) {
        perror           ("Socket is closed, couldn't send data");
        closeConnections (remotehost);
    }
    pthread_mutex_unlock   (&sendLocks[lockIndex]);
    return SUCCESS;
}
int multicastTCP(const char *data, const ssize_t datasize, int cacheIndex)
{
    for (int i = 0; i < getCacheOccupancy(cacheIndex); i++) {
        // TODO: perhaps this needs to be done on the thread
        // Pool but should be fine for smaller amount of clients.
        // If one client stalls however, that stalls all the packets in
        // the multicast.
        sendDataTCP(data, datasize, getHostFromCache(cacheIndex, i));
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
