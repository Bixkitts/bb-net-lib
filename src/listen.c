#include <sys/types.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>
#include <malloc.h>
#include <fcntl.h>

#include "clientObject.h"
#include "listen.h"
#include "defines.h"
#include "socketsNetLib.h"
#include "threadPool.h"
#include "send.h"

threadPool TCPthreadPool = NULL;
threadPool UDPthreadPool = NULL;

typedef struct {
    Host       *localhost;
    Host       *remotehost;
    char       *buffer;
    ssize_t     bytesToProcess;
    void      (*packet_handler)(char*, ssize_t, Host*);
} packetReceptionArgs;

static void receiveTCPpackets          (packetReceptionArgs *args);
static void destroyPacketReceptionArgs (packetReceptionArgs **args);

int listenForUDP(Host *localhost, void (*packet_handler)(char*, ssize_t, Host*))    //Should be called on it's own thread as the while loop is blocking 
{    
    const socketfd sockfd                     = createSocket(SOCK_DEFAULT_UDP);
    Host           remotehost                 = { 0 };
    ssize_t        numBytes                   = 0;
    socklen_t      len                        = 0;
    char           buffer[PACKET_BUFFER_SIZE] = { 0 };

    struct timeval timeout;
    timeout.tv_sec = 5;   // 5 seconds
    timeout.tv_usec = 0;  // 0 microseconds

    if (FAILURE(setsockopt(sockfd, 
                           SOL_SOCKET, 
                           SO_RCVTIMEO, 
                           (char *)&timeout, 
                           sizeof(timeout)))) 
    {
        perror("setsockopt");
    }

    if (FAILURE(bindSocket(sockfd, 
                           localhost)))
    {
        perror("Failed to listen for UDP \n");
        return ERROR;
    }

    setCommunicating(localhost);
    setCommunicating(&remotehost);

    len = sizeof(localhost->address);
    // Need to cast the pointer to a sockaddr type to satisfy the syscall
    struct sockaddr* remoteAddress = ( struct sockaddr *)&remotehost.address;

    while(isCommunicating(localhost)) {
        numBytes = recvfrom(sockfd, 
                            buffer, 
                            PACKET_BUFFER_SIZE, 
                            MSG_WAITALL, 
                            remoteAddress, 
                           &len);

        if (numBytes < PACKET_BUFFER_SIZE) {
            buffer[numBytes] = '\0';    // Null terminate the received data
        }

        if (numBytes == 0) {
            printf("Transmission finished\n");
            break;
        }
        // TODO: this is currently blocking and should run in it's own thread from
        // the pool, but I don't need UDP right now and even if I did it should be _okay_
        // for a small amount of hosts.
        packet_handler(buffer, numBytes, &remotehost);
    }

    if (isCommunicating(localhost)) {
        closeConnections(localhost);
    }
    if (isCommunicating(&remotehost)) {
        closeConnections(&remotehost);
    }

    return SUCCESS;
}

/*
 * Core TCP listening function.
 * Call it once and it will block
 * and listen until the localhost
 * is set not to listen any more.
 * */
int listenForTCP(Host *localhost, 
                 void (*packet_handler)(char*, ssize_t, Host*))
{
#ifdef DEBUG
    fprintf(stderr, "\nListening for TCP connections...");
#endif
    packetReceptionArgs *receptionArgs   = NULL;
    socklen_t            addrLen         = 0;
    struct sockaddr     *remoteAddress   = NULL;
    Host                *remotehost      = NULL;

    createThreadPool (&TCPthreadPool);
    setSocket        (localhost, createSocket(SOCK_DEFAULT_TCP));

    if (FAILURE(bindSocket(getSocket(localhost), localhost)))
    {
        perror("\nFailed to listen for TCP");
        return ERROR;
    }

    setCommunicating(localhost);
    if (FAILURE(listen(getSocket(localhost), SOCK_BACKLOG))) {
        printf("\nError: listen() failed with errno %d: %s\n", errno, strerror(errno));
        return ERROR;
    }

    while(isCommunicating(localhost)) 
    {
        remotehost = createHost("", 0000);
        addrLen    = sizeof(remotehost->address);

        // Need to cast the type because that's
        // just how sockets work
        remoteAddress = ( struct sockaddr *)&remotehost->address;

        // The socket file descriptor in "remotehost" becomes an accepted
        // TCP connection, configure it and pass it over
        // to the thread pool.
        setSocket        (remotehost, createSocket(accept(getSocket(localhost), remoteAddress, &addrLen)));
        setCommunicating (remotehost);

        // 5 second timeout to close socket
        // -----------------------------------
        struct timeval timeout = {};
        timeout.tv_sec  = 5;   // 5 seconds
        timeout.tv_usec = 0;  // 0 microseconds
        if (FAILURE(setsockopt(getSocket(remotehost), 
                               SOL_SOCKET, 
                               SO_RCVTIMEO, 
                               (char *)&timeout, sizeof(timeout)))) 
        {
            perror("\nSetsockopt error");
        }
        // ----------------------------------

        receptionArgs = (packetReceptionArgs*)calloc(1, sizeof(packetReceptionArgs));
        if (receptionArgs == NULL) {
            goto early_exit;
        }

        // Remotehost pointer is now owned by new thread
        receptionArgs->remotehost     = remotehost;
        receptionArgs->localhost      = localhost;
        receptionArgs->packet_handler = packet_handler;
        receptionArgs->buffer         = (char*)calloc(PACKET_BUFFER_SIZE*5, sizeof(char));
        receptionArgs->bytesToProcess = 0;

        addTaskToThreadPool(TCPthreadPool, (void*)receiveTCPpackets, receptionArgs);
    }

early_exit: 
    destroyThreadPool (&TCPthreadPool);
    closeSocket       (getSocket(localhost));

    if (isCommunicating(localhost)) {
        closeConnections(localhost);
    }
    if (isCommunicating(remotehost)) {
        closeConnections(remotehost);
    }

    return SUCCESS;
}

static void receiveTCPpackets(packetReceptionArgs *args) 
{
    //addTaskToThreadPool(TCPthreadPool, (void*)processTCPpackets, args);
#ifdef DEBUG
    fprintf(stderr, "\nReceiving a TCP packet in a thread...");
#endif
    ssize_t numBytes = 0;
    
    while(isCommunicating(args->remotehost)) {
        numBytes = recv(getSocket(args->remotehost), 
                         args->buffer, 
                         PACKET_BUFFER_SIZE, 
                         0);
        if (numBytes > 0) {
            args->packet_handler(args->buffer, numBytes, args->remotehost); 
            sleep(1);
        }
        else {
            fprintf(stderr, "\nConnection shutdown triggered by recv()...");
            closeConnections(args->remotehost);
        }
    }
    // Let the remote host know we're closing connection
    sendDataTCP                (NULL, 0, args->remotehost);
    closeSocket                (getSocket(args->remotehost));
    destroyPacketReceptionArgs (&args);
    return;
}

/*
 * Precondition that args pointer and members not NULL
 */
static void destroyPacketReceptionArgs(packetReceptionArgs **args)
{
    if (*args == NULL) {
        return;
    }
    destroyHost (&(*args)->remotehost); 
    free        ((*args)->buffer);
    free        (*args);
    *args = NULL;
}
