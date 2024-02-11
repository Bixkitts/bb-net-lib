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
#include "socketsNetLib.h"
#include "threadPool.h"


typedef struct {
    char     *buffer;
    uint16_t  bufsize;
    Client    localhost;
    Client    remotehost;
    void    (*packet_handler)(char*, uint16_t, Client*);
} packetReceptionArgs;

static void receiveTCPpackets          (packetReceptionArgs *args);
static void destroyPacketReceptionArgs (packetReceptionArgs *args);

int listenForUDP(Client *localhost, void (*packet_handler)(char*, uint16_t, Client*))    //Should be called on it's own thread as the while loop is blocking 
{    
    const socketfd sockfd     = createSocket(SOCK_DEFAULT_UDP);
    Client         remotehost = { 0 };
    int64_t        numBytes   = 0;
    socklen_t      len        = 0;



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

    setListening(localhost);
    setListening(&remotehost);

    len = sizeof(localhost->address);
    // Need to cast the pointer to a sockaddr type to satisfy the syscall
    struct sockaddr* remoteAddress = ( struct sockaddr *)&remotehost.address;

    while(isListening(localhost) && isListening(&remotehost)) // We can shut this down by calling unsetListeninging on the client
    {
        numBytes = recvfrom(sockfd, buffer, bufsize, MSG_WAITALL, remoteAddress, &len);
        buffer[numBytes] = '\0';    // Null terminate the received data

        if (numBytes == 0) 
        {
            printf("Transmission finished\n");
            break;
        }
        packet_handler(buffer, bufsize, remotehost);
    }

    if (isListening(localhost))
        unsetListening(localhost);
    if (isListening(remotehost))
        unsetListening(remotehost);

    return SUCCESS;
}

/*
 * Core TCP listening function.
 * Call it once and it will block
 * and listen until the localhost
 * is set not to listen any more.
 * */
int listenForTCP(Client *localhost, 
                 void (*packet_handler)(char*, uint16_t, Client*))
{
    threadPool           localThreadPool = NULL;
    packetReceptionArgs *receptionArgs   = NULL;
    socklen_t            addrLen             = 0;
    struct sockaddr     *remoteAddress   = NULL;
    Client               remotehost      = { 0 };

    initThreadPool (localThreadPool);
    setSocket      (localhost, createSocket(SOCK_DEFAULT_TCP));

    if (FAILURE(bindSocket(getSocket(localhost), localhost)))
    {
        perror("Failed to listen for TCP \n");
        return ERROR;
    }

    setListening(localhost);
    // Still need to patch this up for multiple conections
    if (FAILURE(listen(getSocket(localhost), SOCK_BACKLOG))) {
        printf("Error: listen() failed with errno %d: %s\n", errno, strerror(errno));
        return ERROR;
    }


    while(isListening(localhost)) 
    {
        addrLen       = sizeof(remotehost.address);

        // Need to cast the type because that's
        // just how sockets work
        remoteAddress = ( struct sockaddr *)&remotehost.address;

        // The socket file descriptor in "remotehost" becomes an accepted
        // TCP connection, configure it and pass it over
        // to the thread pool.
        setSocket    (&remotehost, createSocket(accept(getSocket(localhost), remoteAddress, &addrLen)));
        setListening (&remotehost);

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
        copyClient (&receptionArgs->remotehost, &remotehost);
        copyClient (&receptionArgs->localhost, localhost);
        receptionArgs->packet_handler = packet_handler;
        // ------------------------------------------------

        // Process the TCP data in a thread, continue with this loop
        // accepting connections and getting valid socket
        // file descriptors to pass to threads.
        // remotehost data is passed off here.
        addTaskToThreadPool(localThreadPool, (void*)receiveTCPpackets, &receptionArgs);
    }

early_exit: 
    destroyThreadPool (localThreadPool);
    closeSocket       (getSocket(localhost));

    if (isListening(localhost)) {
        unsetListening(localhost);
    }
    if (isListening(&remotehost)) {
        unsetListening(&remotehost);
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
    int64_t numBytes;
    // Receive data continuously until client closes 
    // Receive TCP packet from client and store in buffer
    while(isListening(&args->remotehost))
    {
        numBytes = recv(getSocket(&args->remotehost), args->buffer, args->bufsize, 0);
        if (numBytes > 0)
        {
            args->buffer[numBytes] = '\0'; // Null terminate the received data
            args->packet_handler(args->buffer, args->bufsize, &args->remotehost);
        }
        else if (numBytes == 0)
        {
            (void)printf("\nClient negotiated connection close/timeout\n");
            closeSocket    (getSocket(&args->remotehost));
            unsetListening (&args->remotehost);
        }
        else if (numBytes == -1)
        {
            (void)printf("\nError: recv() failed with errno %d: %s\n", errno, strerror(errno));
            closeSocket    (getSocket(&args->remotehost));
            unsetListening (&args->remotehost);
            return;
        }
    }
    closeSocket                (getSocket(&args->remotehost));
    destroyPacketReceptionArgs (args);
    return;
}

/*
 * Precondition that args pointer and members not NULL
 */
static void destroyPacketReceptionArgs(packetReceptionArgs *args)
{
    free(args->buffer);
    free(args);
}
