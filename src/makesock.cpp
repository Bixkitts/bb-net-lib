#include <iostream>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <strings.h>
#include <unistd.h>
#include "clientObject.h"
Client* createClient(char *ip, u_short port)
{
    Client* client = new Client;
     
    if ( (client->sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0 ) { 
        perror("socket creation failed"); //perror is a system call to write an error.
        exit(EXIT_FAILURE);
    }   
    //"bzero" is a syscall to zero all the bytes
    bzero((char *) &client->Socket, sizeof(client->Socket));
  
    //filling in the data of the client's ip.
    client->Socket.sin_family = AF_INET;
    client->Socket.sin_port = htons(port);
    inet_pton(AF_INET, ip, &client->Socket.sin_addr);
    //bind the socket "client->sockfd" to the address and port in the sockaddr struct "client->Socket"
    int b = bind(client->sockfd, (struct sockaddr *) &client->Socket, sizeof(client->Socket));

    if(b == 0)
        printf("Bound socket successfully \n");
    else
        printf("Socket could not be bound, exiting \n");

    return client;
}

void removeClient(Client* client)
{
    close(client->sockfd);
    delete client;
}
