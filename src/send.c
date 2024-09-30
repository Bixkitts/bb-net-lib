#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <strings.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>

#include "clientObject.h"
#include "listen.h"
#include "socketsNetLib.h"
#include "send.h"

#define SEND_LOCK_COUNT 32


// Global switch for how packets should be sent
enum packet_sender_type packetSenderType = PACKET_SENDER_TCP;

typedef ssize_t (*PacketSender)(struct packet_sending_args*);
static inline ssize_t send_TCP_unencrypted (struct packet_sending_args *args);
static inline ssize_t send_TCP_encrypted   (struct packet_sending_args *args);
static int            waitForReady         (int sockfd);
static PacketSender send_variants[PACKET_SENDER_COUNT] = 
{ 
            send_TCP_unencrypted,
            send_TCP_encrypted
};


// We use these locks to make each TCP transfer on a socket a critical section
// and do it on multiple sockets simultaneously.
static pthread_mutex_t sendLocks[SEND_LOCK_COUNT]  = {PTHREAD_MUTEX_INITIALIZER};

void setTCP_sendType (enum packet_sender_type type)
{
    packetSenderType = type;
}

int sendDataUDP(const char *data, const ssize_t datasize, struct host *remotehost)
{
#ifdef DEBUG
    fprintf(stderr, "\nSending UDP packet...");
#endif
    socketfd_t  sockfd                     = getSocket(remotehost);
    socklen_t len                        = sizeof(remotehost->address);    
    const struct sockaddr* remoteAddress = NULL;

    remoteAddress = (const struct sockaddr *) &remotehost->address; 
    sendto (sockfd, data, datasize, MSG_CONFIRM, remoteAddress, len);
    
    return SUCCESS;
}

static inline ssize_t send_TCP_unencrypted (struct packet_sending_args *args)
{
    return send(getSocket(args->remotehost), args->buffer, args->bytesToProcess, 0);
}
static inline ssize_t send_TCP_encrypted (struct packet_sending_args *args)
{
    return SSL_write(getHostSSL(args->remotehost), args->buffer, args->bytesToProcess);
}
static int waitForReady(int sockfd)
{
    fd_set writefds;
    FD_ZERO(&writefds);
    FD_SET(sockfd, &writefds);

    int selectStatus = select(sockfd + 1,
                              NULL,
                              &writefds,
                              NULL,
                              NULL);
    if (selectStatus < 0) {
        perror("Select error");
        return -1;
    }
    return selectStatus > 0;
}
int sendDataTCP(const char *data, const size_t datasize, struct host *remotehost)
{
#ifdef DEBUG
    fprintf(stderr, "\nSending TCP packet...");
#endif
    int               lockIndex      = getHostID(remotehost) % SEND_LOCK_COUNT;
    ssize_t           totalBytesSent = 0;
    ssize_t           status         = 0;
    struct packet_sending_args sendArgs       = {remotehost, data, datasize};
    pthread_mutex_lock(&sendLocks[lockIndex]);
    while (totalBytesSent < datasize) {
        // A switch to send packets in different ways
        status = send_variants[packetSenderType](&sendArgs);

        if (status == -1) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                if (waitForReady(getSocket(remotehost)) < 0) {
                    perror              ("\nSelect error");
                    closeConnections    (remotehost);
                    pthread_mutex_unlock(&sendLocks[lockIndex]);
                    return ERROR;
                }
                continue;
            }

            perror               ("\nFailed to send TCP message");
            closeConnections     (remotehost);
            pthread_mutex_unlock (&sendLocks[lockIndex]);
            return ERROR;
        }
        if (status == 0) {
            fprintf          (stderr, "\nSocket is closed, couldn't send data");
            closeConnections (remotehost);
            pthread_mutex_unlock(&sendLocks[lockIndex]);
            return SUCCESS;
        }
        totalBytesSent += status;
    }
    pthread_mutex_unlock(&sendLocks[lockIndex]);
    return SUCCESS;
}

/*
 * TODO: Not currently working,
 * make it work.
 */
int sendDataTCPandRecv(const char *data, 
                       const ssize_t datasize, 
                       struct host *remotehost, 
                       void (*packet_handler)(char*, ssize_t, struct host*))
{
    struct packet_reception_args *recvArgs  = NULL;

    sendDataTCP(data, datasize, remotehost);

    recvArgs = (struct packet_reception_args*)calloc(1, sizeof(struct packet_reception_args));
    if (recvArgs == NULL) {
        closeConnections(remotehost);
        return SEND_ERROR;
    }

    // Remotehost pointer is now owned by new thread
    recvArgs->remotehost     = remotehost;
    recvArgs->localhost      = NULL;
    recvArgs->packet_handler = packet_handler;
    recvArgs->bytesToProcess = 0;
    recvArgs->buffer         = (char*)calloc(PACKET_BUFFER_SIZE*2, sizeof(char));
    if (recvArgs->buffer == NULL) {
        free (recvArgs);
        return SEND_ERROR;
    }
        
    receiveTCPpackets (recvArgs);
    return SUCCESS;
}

/*
 * Returns the amount of bytes
 * sent, or -1 for an error OR -2
 * Call this function until it errors
 * or sends datasize bytes
 */
static ssize_t sendDataTCP_NB(const char *data, 
                              const ssize_t datasize, 
                              struct host *remotehost)
{
#ifdef DEBUG
    fprintf(stderr, "\nSending TCP packet...");
#endif
    int               lockIndex      = getHostID(remotehost) % SEND_LOCK_COUNT;
    ssize_t           status         = 0;
    struct packet_sending_args sendArgs       = {remotehost, data, datasize};
    pthread_mutex_lock   (&sendLocks[lockIndex]);
        // A switch to send packets in different ways
    status = send_variants[packetSenderType](&sendArgs);

    if (status == -1) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return SEND_TRYAGAIN;
        }
        perror("\nFailed to send TCP message");
        closeConnections     (remotehost);
        pthread_mutex_unlock (&sendLocks[lockIndex]);
        return SEND_ERROR;
    }
    if (status == 0) {
        fprintf          (stderr, "\nSocket is closed, couldn't send data");
        closeConnections (remotehost);
        pthread_mutex_unlock   (&sendLocks[lockIndex]);
        return SUCCESS;
    }
    pthread_mutex_unlock   (&sendLocks[lockIndex]);
    return status;
}

int multicastTCP(const char *data, const ssize_t datasize, int cacheIndex)
{
#ifdef DEBUG
    fprintf(stderr, "\nMulticasting to cache number %d...", cacheIndex);
#endif
    struct host      *remotehost  = NULL;
    bool       tryAgain    = 1;
    ssize_t    currentStatus = 0;
    ssize_t    statuses[MAX_HOSTS_PER_CACHE] = { 0 };

    for (int i = 0; i < MAX_HOSTS_PER_CACHE; i++) {
        statuses[i] = SEND_TRYAGAIN;
    }
    while (tryAgain == true) {
        tryAgain = false;
        for (int i = 0; i < MAX_HOSTS_PER_CACHE; i++) {
            remotehost    = getHostFromCache(cacheIndex, i);
            if (remotehost == NULL) {
                continue;
            }
            currentStatus = statuses[i];
            if ((currentStatus < datasize && currentStatus > 0)
                || currentStatus == SEND_TRYAGAIN) {
                currentStatus =
                sendDataTCP_NB(data, datasize, remotehost);
                tryAgain = (currentStatus < datasize 
                           && currentStatus > 0
                           && tryAgain == 0)
                           || currentStatus == SEND_TRYAGAIN;
            }
        }
    }
    return SUCCESS;
}

int connectToTCP(struct host *remotehost)
{
    const socketfd_t   sockfd        = createSocket(SOCK_DEFAULT_TCP);
    struct sockaddr* remoteAddress = (struct sockaddr *)&remotehost->address;
    const socklen_t  sizeOfAddress = sizeof(remotehost->address);
    if (FAILURE(connect(sockfd, remoteAddress, sizeOfAddress))) {
        perror("\nConnect failed");
        return ERROR;
    }
    setSocket        (remotehost, sockfd);
    return SUCCESS;
}
