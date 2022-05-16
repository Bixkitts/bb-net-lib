#include <iostream>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <strings.h>
#include <unistd.h>
#include "clientObject.h"
namespace netlib
{
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
        bind(client->sockfd, (struct sockaddr *) &client->Socket, sizeof(client->Socket));

        return client;
    }

    int removeClient(Client* client)
    {
        close(client->sockfd);
        delete client;

        return 0;
    }
}
