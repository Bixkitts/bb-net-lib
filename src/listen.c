#include <sys/types.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>

#include "clientObject.h"
#include "listen.h"
#include "socketsNetLib.h"

static int receiveTCPpackets(char *buffer, const uint16_t bufsize, Client* remotehost, Client *localhost, void (*packet_handler)(char*, uint16_t, Client*)) ;


int listenForUDP(char *buffer, const uint16_t bufsize, Client *localhost, Client *remotehost, void (*packet_handler)(char*, uint16_t, Client*))    //Should be called on it's own thread as the while loop is blocking 
{    
    const socketfd sockfd = createSocket(SOCK_DEFAULT_UDP);

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
    setListening(remotehost);

    int64_t numBytes;
    socklen_t len = sizeof(localhost->address);
    // Need to cast the pointer to a sockaddr type to satisfy the syscall
    struct sockaddr* remoteAddress = ( struct sockaddr *)&remotehost->address;

    while(isListening(localhost) && isListening(remotehost)) // We can shut this down by calling unsetListeninging on the client
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

int listenForTCP(char *buffer, const uint16_t bufsize, Client *localhost, Client *remotehost, void (*packet_handler)(char*, uint16_t, Client*))
{
    setSocket(localhost, createSocket(SOCK_DEFAULT_TCP));

    if (FAILURE(bindSocket(getSocket(localhost), localhost)))
    {
        perror("Failed to listen for TCP \n");
        return ERROR;
    }

    setListening(localhost);

    // Still need to patch this up for multiple conections
    if (FAILURE(listen(getSocket(localhost), SOCK_BACKLOG))) 
    {
        printf("Error: listen() failed with errno %d: %s\n", errno, strerror(errno));
        return ERROR;
    }

    socklen_t len = sizeof(remotehost->address);
    struct sockaddr* remoteAddress = ( struct sockaddr *)&remotehost->address;

    while(isListening(localhost)) 
    {
        // Accept incoming  from remote host
        setSocket(remotehost, createSocket(accept(getSocket(localhost), remoteAddress, &len)));
        setListening(remotehost);

        struct timeval timeout;
        timeout.tv_sec = 5;   // 5 seconds
        timeout.tv_usec = 0;  // 0 microseconds
        if (FAILURE(setsockopt(getSocket(remotehost), SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout)))) 
        {
            perror("\nSetsockopt error");
        }

        // Receive TCP packets from the connected remote host
        receiveTCPpackets(buffer, bufsize, remotehost, localhost, packet_handler);
    }

    closeSocket(getSocket(localhost));

    if (isListening(localhost))
        unsetListening(localhost);
    if (isListening(remotehost))
        unsetListening(remotehost);

    return SUCCESS;
}

static int receiveTCPpackets(char *buffer, const uint16_t bufsize, Client* remotehost, Client *localhost, void (*packet_handler)(char*, uint16_t, Client*)) 
{
    int64_t numBytes;
    // Receive data continuously until client closes 
        // Receive TCP packet from client and store in buffer
    while(isListening(remotehost))
    {
        numBytes = recv(getSocket(remotehost), buffer, bufsize, 0);
        if (numBytes > 0)
        {
            buffer[numBytes] = '\0'; // Null terminate the received data
            packet_handler(buffer, bufsize, remotehost);
        }
        else if (numBytes == 0)
        {
            (void)printf("\nClient negotiated connection close/timeout\n");
            closeSocket(getSocket(remotehost));
            unsetListening(remotehost);
        }
        else if (numBytes == -1)
        {
            (void)printf("\nError: recv() failed with errno %d: %s\n", errno, strerror(errno));
            closeSocket(getSocket(remotehost));
            unsetListening(remotehost);
            return ERROR;
        }
    }
    closeSocket(getSocket(remotehost));
    return SUCCESS;
}
