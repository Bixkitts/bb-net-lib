#ifndef CLIENTOBJECT
#define CLIENTOBJECT

#include <stdbool.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include "defines.h"
#include "socketfd.h"


typedef struct Client   // Structure that can be expanded and used to hold any needed info
{
    struct sockaddr_in address;         // The socket it contains (IP and port)
    volatile bool bListen;              // Is this client supposed to be currently listening on a thread 
    socketfd associatedSocket;          // Socket that gets associated with this client.
                                        // This allows the socket from a connection 
                                        // to be saved and reused!
} Client;

BBNETAPI extern Client* createClient(const char *ip, const uint16_t port);  // Creates a client with an ip and port
BBNETAPI extern void removeClient(Client* client);                          // Removes a client, closing the socket and freeing the memory
BBNETAPI extern char* getIP(Client* client);                                // Returns a string representation of the IP address in the client

// Checking or setting an interface for listening
extern void startListen(Client* client);       // Sets the bListen boolean
extern void stopListen(Client* client);        // Unsets the bListen boolean
extern bool isListening(const Client* client);
extern void setSocket(Client* client, socketfd sockfd);
extern socketfd getSocket(const Client* client);

#endif
