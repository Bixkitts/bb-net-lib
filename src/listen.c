#include <sys/types.h>
#include <stdio.h>
#include <strings.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include "clientObject.h"
#include "socketPool.h"

int listenForUDP(char *buffer, uint16_t bufsize, Client *localhost, Client *remotehost)    //Should be called on it's own thread as the while loop is blocking 
{     
    socketIndex index = createSocket();
    startListen(localhost);

    int numBytes;
    socklen_t len = sizeof(localhost->address);

    while(isListening(localhost)) // We can shut this down by calling stopListening on the client
    {
        numBytes = recvfrom(getSocketAtIndex(index), buffer, bufsize, MSG_WAITALL, ( struct sockaddr *)&remotehost->address, &len);
        buffer[numBytes] = '\0';
    }
    return SUCCESS;
}

int receiveTCPpackets(char *buffer, uint16_t bufsize, const Client *localhost) 
{
    int numBytes;
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
    return SUCCESS;
}

int listenForTCP(char *buffer, uint16_t bufsize, Client *localhost, const Client *remotehost)
{
    startListen(localhost);

    // Listen for incoming connections
    if (listen(sockfd, 5) < 0) 
    {
        printf("Error occurred while listening for connections\n");
        return ERROR;
    }

    // Accept incoming connection from remote host
    socklen_t len = sizeof(remotehost->address);

    socketfd sockfd_new = accept(sockfd, (struct sockaddr *)&remotehost->address, &len);
    if (sockfd_new < 0) 
    {
        printf("Error occurred while accepting connection\n");
        return ERROR;
    }

    // Receive TCP packets from the connected remote host
    receiveTCPpackets(buffer, bufsize, sockfd_new, localhost);

    return SUCCESS;
}

static int bindSocket(const socketfd sockfd, const Client *localhost)
{
    //bind the socket "client->sockfd" to the address and port in the sockaddr struct "client->Socket"
    int b = bind(sockfd, (struct sockaddr *) &localhost->address, sizeof(localhost->address));

    if(b == 0)
        printf("Bound socket successfully \n");
    else
        printf("Socket could not be bound, exiting \n");

    return SUCCESS;
}
