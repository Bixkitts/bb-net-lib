#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <strings.h>
#include <unistd.h>

#include "clientObject.h"

Client* createClient(char *ip, u_short port)
{
    Client* client;
    client = (struct Client*) malloc(sizeof(struct Client));
    stopListen(client);
    if ( (client->sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0 ) { 
        perror("socket creation failed"); //perror is a system call to write an error.
        exit(EXIT_FAILURE);
    }   
    //"bzero" is a syscall to zero all the bytes
    bzero((char *) &client->socket, sizeof(client->socket));

    //filling in the data of the client's ip.
    client->socket.sin_family = AF_INET;
    client->socket.sin_port = htons(port);
    inet_pton(AF_INET, ip, &client->socket.sin_addr);
    //bind the socket "client->sockfd" to the address and port in the sockaddr struct "client->Socket"
    int b = bind(client->sockfd, (struct sockaddr *) &client->socket, sizeof(client->socket));

    if(b == 0)
        printf("Bound socket successfully \n");
    else
    {
        printf("Socket could not be bound, exiting \n");
        EXIT_FAILURE;
    }
    return client;
}

void removeClient(Client* client)
{
    close(client->sockfd);
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