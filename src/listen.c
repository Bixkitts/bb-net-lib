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

static int receiveTCPpackets(char *buffer, const uint16_t bufsize, Client* remotehost, const Client *localhost, void (*packet_handler)(char*, uint16_t, Client*)) ;


int listenForUDP(char *buffer, const uint16_t bufsize, Client *localhost, Client *remotehost, void (*packet_handler)(char*, uint16_t, Client*))    //Should be called on it's own thread as the while loop is blocking 
{    
    const socketfd sockfd = createSocket(SOCK_DEFAULT_UDP);
    if(FAILURE(bindSocket(sockfd, localhost)))
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

    unsetListening(localhost);
    unsetListening(remotehost);

    return SUCCESS;
}

int listenForTCP(char *buffer, const uint16_t bufsize, Client *localhost, Client *remotehost, void (*packet_handler)(char*, uint16_t, Client*))
{
    const socketfd sockfd = createSocket(SOCK_DEFAULT_TCP);
    if(FAILURE(bindSocket(sockfd, localhost)))
    {
        perror("Failed to listen for TCP \n");
        return ERROR;
    }

    setListening(localhost);
    setListening(remotehost);
    // Still need to patch this up for multiple conections
    while(isListening(localhost) && isListening(remotehost))
    {
        if (FAILURE(listen(sockfd, SOCK_BACKLOG))) 
        {
            printf("Error: listen() failed with errno %d: %s\n", errno, strerror(errno));
            return ERROR;
        }

        socklen_t len = sizeof(remotehost->address);
        struct sockaddr* remoteAddress = ( struct sockaddr *)&remotehost->address;

        // Accept incoming  from remote host
        setSocket(remotehost, createSocket(accept(sockfd, remoteAddress, &len)));

        // Receive TCP packets from the connected remote host
        receiveTCPpackets(buffer, bufsize, remotehost, localhost, packet_handler);
    }

    closeSocket(sockfd);

    unsetListening(localhost);
    unsetListening(remotehost);

    return SUCCESS;
}

static int receiveTCPpackets(char *buffer, const uint16_t bufsize, Client* remotehost, const Client *localhost, void (*packet_handler)(char*, uint16_t, Client*)) 
{
    int64_t numBytes;
    // Receive data continuously until client closes 
    while(isListening(localhost) && isListening(remotehost)) 
    {
        // Receive TCP packet from client and store in buffer
        numBytes = recv(getSocket(remotehost), buffer, bufsize, 0);
        buffer[numBytes] = '\0'; // Null terminate the received data

        if (numBytes == 0) 
        {
            printf("Transmission finished\n");
            break;
        }

        packet_handler(buffer, bufsize, remotehost);
    }
    closeSocket(getSocket(remotehost));
    return SUCCESS;
}
