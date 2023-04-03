#ifndef CLIENTOBJECT
#define CLIENTOBJECT

#include <stdbool.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include "defines.h"

typedef struct Client 
{
    struct sockaddr_in socket;          // The socket it contains (IP and port)
    int sockfd;                         // file descriptor for the socket
    volatile bool bListen;              // Is this client supposed to be currently listening on a thread 
} Client;

BBNETAPI extern Client* createClient(char *ip, u_short port);  // Creates a client with an ip and port
BBNETAPI extern void removeClient(Client* client);             // Removes a client, closing the socket and freeing the memory

BBNETAPI extern void startListen(Client* client);       // Sets the bListen boolean
BBNETAPI extern void stopListen(Client* client);        // Unsets the bListen boolean

#endif