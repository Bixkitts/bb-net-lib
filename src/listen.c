#include <sys/types.h>
#include <stdio.h>
#include <strings.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include "clientObject.h"

int listenForUDP(char *buffer, uint16_t bufsize, Client *localhost, Client *remotehost)    //Should be called on it's own thread as the while loop is blocking 
{                                                                    
    startListen(localhost);

    int numBytes;
    socklen_t len = sizeof(localhost->socket);

    while(localhost->bListen == 1)
    {
        numBytes = recvfrom(localhost->sockfd, buffer, bufsize, MSG_WAITALL, ( struct sockaddr *)&remotehost->socket, &len);
        buffer[numBytes] = '\0';
    }
    return 0;
}

void receiveTCPpackets(char *buffer, uint16_t bufsize, Client *localhost, Client *remotehost) 
{
    int numBytes;
    // Receive data continuously until client closes connection
    while(localhost->bListen == 1) 
    {
        // Receive TCP packet from client and store in buffer
        numBytes = recv(remotehost->sockfd, buffer, bufsize, 0);
        if (numBytes <= 0) 
        {
            printf("Error occurred while receiving data\n");
            break;
        }
    }
}

int listenForTCP(char *buffer, uint16_t bufsize, Client *localhost, Client *remotehost)
{
    startListen(localhost);

    // Listen for incoming connections
    if (listen(localhost->sockfd, 5) < 0) 
    {
        printf("Error occurred while listening for connections\n");
        return -1;
    }

    // Accept incoming connection from client
    struct sockaddr_in cli_addr;
    socklen_t cli_len = sizeof(cli_addr);

    remotehost->sockfd = accept(localhost->sockfd, (struct sockaddr *)&cli_addr, &cli_len);
    if (remotehost->sockfd < 0) 
    {
        printf("Error occurred while accepting connection\n");
        return -1;
    }

    // Receive TCP packets from the connected client
    receiveTCPpackets(buffer, bufsize, localhost, remotehost);

    return 0;
}
