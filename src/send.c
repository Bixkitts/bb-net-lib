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

// We use these locks to make each TCP transfer on a socket a critical section
// and do it on multiple sockets simultaneously.
static pthread_mutex_t sendLocks[SEND_LOCK_COUNT]  = {PTHREAD_MUTEX_INITIALIZER};

int sendDataUDP(const char *data, const ssize_t datasize, Host *remotehost)
{
#ifdef DEBUG
    fprintf(stderr, "\nSending UDP packet...");
#endif
    socketfd  sockfd                     = getSocket(remotehost);
    socklen_t len                        = sizeof(remotehost->address);    
    const struct sockaddr* remoteAddress = NULL;

    remoteAddress = (const struct sockaddr *) &remotehost->address; 
    sendto (sockfd, data, datasize, MSG_CONFIRM, remoteAddress, len);
    
    return SUCCESS;
}

int sendDataTCP(const char *data, const ssize_t datasize, Host *remotehost)
{
#ifdef DEBUG
    fprintf(stderr, "\nSending TCP packet...");
#endif
    int lockIndex = getHostID(remotehost) % SEND_LOCK_COUNT;
    pthread_mutex_lock   (&sendLocks[lockIndex]);

    int status = send(getSocket(remotehost), data, datasize, 0);

    if (status == -1) {
        perror("\nFailed to send TCP message");
        closeConnections     (remotehost);
        pthread_mutex_unlock (&sendLocks[lockIndex]);
        return ERROR;
    }
    if (status == 0) {
        perror           ("\nSocket is closed, couldn't send data");
        closeConnections (remotehost);
    }
    pthread_mutex_unlock   (&sendLocks[lockIndex]);
    return SUCCESS;
}

int multicastTCP(const char *data, const ssize_t datasize, int cacheIndex)
{
#ifdef DEBUG
    fprintf(stderr, "\nMulticasting to cache number %d...", cacheIndex);
#endif
    Host *remotehost = NULL;
    for (int i = 0; i < getCacheOccupancy(cacheIndex); i++) {
        // TODO: perhaps this needs to be done on the thread
        // Pool but should be fine for smaller amount of clients.
        // If one client stalls however, that stalls all the packets in
        // the multicast.
        remotehost = getHostFromCache(cacheIndex, i);
        if (remotehost != NULL) { 
            sendDataTCP(data, datasize, remotehost);
        }
    }
    return SUCCESS;
}

int connectToTCP(Host *remotehost)
{
    const socketfd   sockfd        = createSocket(SOCK_DEFAULT_TCP);
    struct sockaddr* remoteAddress = (struct sockaddr *)&remotehost->address;
    const socklen_t  sizeOfAddress = sizeof(remotehost->address);
    if (FAILURE(connect(sockfd, remoteAddress, sizeOfAddress))) {
        perror("\nConnect failed");
        return ERROR;
    }
    setSocket(remotehost, sockfd);
    return SUCCESS;
}
