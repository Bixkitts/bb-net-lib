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
    void (*packet_handler)(char*, uint16_t, struct Client*);
} Client;

BBNETAPI extern Client* createClient(const char *ip, const uint16_t port);
BBNETAPI extern void removeClient(Client* client);                          // Removes a client, closing the socket and freeing the memory
BBNETAPI extern char* getIP(Client* client);                                // Returns a string representation of the IP address in the client
BBNETAPI extern void callClientPacketHandler(char* data, uint16_t size, Client* client);
BBNETAPI extern void setClientPacketHandler(Client* client, void (*packet_handler)(char*, uint16_t, Client*));
BBNETAPI extern void (*getClientPacketHandler(Client* client))(char*, uint16_t, Client*);

// Checking or setting an interface for listening
extern void setListening(Client* client);       // Sets the bListen boolean
extern void unsetListening(Client* client);        // Unsets the bListen boolean
extern bool isListening(const Client* client);
BBNETAPI extern void setSocket(Client* client, socketfd sockfd);
BBNETAPI extern socketfd getSocket(const Client* client);

#endif
