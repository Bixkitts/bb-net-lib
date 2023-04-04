#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <strings.h>
#include <unistd.h>

#include "clientObject.h"

Client* createClient(const char *ip, const u_short port)
{
    Client* client;
    client = (struct Client*) malloc(sizeof(struct Client));
    stopListen(client);
    
    bzero((char *) &client->address, sizeof(client->address));

    //filling in the data of the client's ip.
    client->address.sin_family = AF_INET;
    client->address.sin_port = htons(port);
    inet_pton(AF_INET, ip, &client->address.sin_addr);

    return client;
}

socketfd createSocket()
{
    socketfd sockfd;
    if ( (sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0 ) 
    { 
        perror("socket creation failed"); 
    }   
    return sockfd;
}

void removeClient(Client* client)
{
    free(client);
}

void stopListen(Client* client)
{
    client->bListen = 0;
}

void startListen(Client* client)
{
    client->bListen = 1;
}

bool isListening(const Client* client)
{
    return client->bListen;
}