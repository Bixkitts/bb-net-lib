#include <sys/types.h>
#include <stdio.h>
#include <stdint.h>
#include <strings.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "clientObject.h"
#include "listen.h"
#include "socketsNetLib.h"

int listenForUDP(char *buffer, const uint16_t bufsize, Client *localhost, Client *remotehost)    //Should be called on it's own thread as the while loop is blocking 
{    
    const socketfd sockfd = createSocket(SOCK_DEFAULT);
    if(FAILURE(bindSocket(sockfd, localhost)))
    {
        perror("Failed to listen for UDP connection");
        return ERROR;
    }
    startListen(localhost);

    int64_t numBytes;
    socklen_t len = sizeof(localhost->address);
    // Need to cast the pointer to a sockaddr type to satisfy the syscall
    struct sockaddr* remoteAddress = ( struct sockaddr *)&remotehost->address;

    while(isListening(localhost)) // We can shut this down by calling stopListening on the client
    {
        numBytes = recvfrom(sockfd, buffer, bufsize, MSG_WAITALL, remoteAddress, &len);
        buffer[numBytes] = '\0';    // Null terminate the received data
        if (numBytes <= 0) 
        {
            perror("Error occurred while receiving data\n");
            break;
        }
    }
    stopListen(localhost);
    return SUCCESS;
}

int listenForTCP(char *buffer, const uint16_t bufsize, Client *localhost, const Client *remotehost)
{
    const socketfd sockfd = createSocket(SOCK_DEFAULT);
    if(FAILURE(bindSocket(sockfd, localhost)))
    {
        perror("Failed to listen for TCP connection");
        return ERROR;
    }
    startListen(localhost);
    while(isListening(localhost))
    {
        if (listen(sockfd, SOCK_BACKLOG) < 0) 
        {
            printf("Error occurred while listening for connections\n");
            return ERROR;
        }
        break;
    }

    socklen_t len = sizeof(remotehost->address);
    struct sockaddr* remoteAddress = ( struct sockaddr *)&remotehost->address;

    // Accept incoming connection from remote host
    const socketfd sockfd_new = createSocket(accept(sockfd, remoteAddress, &len));

    // Receive TCP packets from the connected remote host
    receiveTCPpackets(buffer, bufsize, sockfd_new, localhost);
    
    closeSocket(sockfd);
    stopListen(localhost);
    return SUCCESS;
}

int receiveTCPpackets(char *buffer, const uint16_t bufsize, const socketfd sockfd, const Client *localhost) 
{
    int64_t numBytes;
    // Receive data continuously until client closes connection
    while(isListening(localhost)) 
    {
        // Receive TCP packet from client and store in buffer
        numBytes = recv(sockfd, buffer, bufsize, 0);
        if (numBytes <= 0) 
        {
            printf("Error occurred while receiving data\n");
            break;
        }
    }
    closeSocket(sockfd);
    return SUCCESS;
}
