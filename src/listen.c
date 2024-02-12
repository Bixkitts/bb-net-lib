#include <sys/types.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>
#include <malloc.h>

#include "clientObject.h"
#include "listen.h"
#include "defines.h"
#include "socketsNetLib.h"
#include "threadPool.h"


typedef struct {
    Host    localhost;
    Host    remotehost;
    void    (*packet_handler)(char*, int16_t, Host*);
} packetReceptionArgs;

static void receiveTCPpackets          (packetReceptionArgs *args);
static void destroyPacketReceptionArgs (packetReceptionArgs **args);

int listenForUDP(Host *localhost, void (*packet_handler)(char*, int16_t, Host*))    //Should be called on it's own thread as the while loop is blocking 
{    
    const socketfd sockfd     = createSocket(SOCK_DEFAULT_UDP);
    Host           remotehost = { 0 };
    int16_t        numBytes   = 0;
    socklen_t      len        = 0;
    char          *buffer     = NULL;
    // Need to track the size of the buffer
    // we'll be using to hold received data.
    // We may need to make it bigger with reallocations.
    int            allocSize  = 0 * PACKET_BUFFER_SIZE;


    struct timeval timeout;
    timeout.tv_sec = 5;   // 5 seconds
    timeout.tv_usec = 0;  // 0 microseconds

    if (FAILURE(setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout)))) 
    {
        perror("setsockopt");
    }

    if (FAILURE(bindSocket(sockfd, localhost)))
    {
        perror("Failed to listen for UDP \n");
        return ERROR;
    }

    setCommunicating(localhost);
    setCommunicating(&remotehost);

    len = sizeof(localhost->address);
    // Need to cast the pointer to a sockaddr type to satisfy the syscall
    struct sockaddr* remoteAddress = ( struct sockaddr *)&remotehost.address;

    buffer = (char*)malloc(PACKET_BUFFER_SIZE);
    if (buffer == NULL) {
        return ERROR;
    }

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

        if (numBytes == 0) 
        {
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
                 void (*packet_handler)(char*, int16_t, Host*))
{
    threadPool           localThreadPool = NULL;
    packetReceptionArgs *receptionArgs   = NULL;
    socklen_t            addrLen             = 0;
    struct sockaddr     *remoteAddress   = NULL;
    Host                 remotehost      = { 0 };

    initThreadPool (localThreadPool);
    setSocket      (localhost, createSocket(SOCK_DEFAULT_TCP));

    if (FAILURE(bindSocket(getSocket(localhost), localhost)))
    {
        perror("Failed to listen for TCP \n");
        return ERROR;
    }

    setCommunicating(localhost);
    if (FAILURE(listen(getSocket(localhost), SOCK_BACKLOG))) {
        printf("Error: listen() failed with errno %d: %s\n", errno, strerror(errno));
        return ERROR;
    }


    while(isCommunicating(localhost)) 
    {
        addrLen       = sizeof(remotehost.address);

        // Need to cast the type because that's
        // just how sockets work
        remoteAddress = ( struct sockaddr *)&remotehost.address;

        // The socket file descriptor in "remotehost" becomes an accepted
        // TCP connection, configure it and pass it over
        // to the thread pool.
        setSocket        (&remotehost, createSocket(accept(getSocket(localhost), remoteAddress, &addrLen)));
        setCommunicating (&remotehost);

        // Set a timeout on the socket.
        // The underlying system SHOULD close
        // a connection if this is exhausted.
        struct timeval timeout = {};
        timeout.tv_sec  = 5;   // 5 seconds
        timeout.tv_usec = 0;  // 0 microseconds
        if (FAILURE(setsockopt(getSocket(&remotehost), 
                               SOL_SOCKET, 
                               SO_RCVTIMEO, 
                               (char *)&timeout, sizeof(timeout)))) 
        {
            perror("\nSetsockopt error");
        }

        receptionArgs = (packetReceptionArgs*)calloc(1, sizeof(packetReceptionArgs));
        if (receptionArgs == NULL) {
            // returns SUCCESS but whatever.
            goto early_exit;
        }

        // Deep copy of hosts for thread-local processing
        // Buffer and bufsize filled later in the thread
        // while receiving data.
        copyHost (&receptionArgs->remotehost, &remotehost);
        copyHost (&receptionArgs->localhost, localhost);
        receptionArgs->packet_handler = packet_handler;

        // Process the TCP data in a thread, continue with this loop
        // accepting connections and getting valid socket
        // file descriptors to pass to threads.
        // remotehost data is passed off here.
        addTaskToThreadPool(localThreadPool, (void*)receiveTCPpackets, &receptionArgs);
    }

early_exit: 
    destroyThreadPool (localThreadPool);
    closeSocket       (getSocket(localhost));

    if (isCommunicating(localhost)) {
        closeConnections(localhost);
    }
    if (isCommunicating(&remotehost)) {
        closeConnections(&remotehost);
    }

    return SUCCESS;
}
/*
 * A connection has successfully been opened with listenForTCP.
 * receiveTCPpackets() should now be running in it's own thread
 * reading it's own copied thread-local "args" data.
 */
static void receiveTCPpackets(packetReceptionArgs *args) 
{
    int16_t  numBytes                   = 0;
    char     buffer[PACKET_BUFFER_SIZE] = { 0 };   

    while(isCommunicating(&args->remotehost)) {
        numBytes       =  recv (getSocket(&args->remotehost), 
                                buffer, 
                                PACKET_BUFFER_SIZE, 
                                0);
        args->packet_handler (buffer, numBytes, &args->remotehost);
    }
    closeSocket                (getSocket(&args->remotehost));
    destroyPacketReceptionArgs (&args);
    return;
}

/*
 * Precondition that args pointer and members not NULL
 */
static void destroyPacketReceptionArgs(packetReceptionArgs **args)
{
    if (*args != NULL) {
        free(*args);
        *args = NULL;
    }
}
