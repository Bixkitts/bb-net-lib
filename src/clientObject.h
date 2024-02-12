#ifndef hostOBJECT
#define hostOBJECT

#include <stdbool.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>

#include "defines.h"
#include "socketfd.h"


typedef struct Host  // Structure that can be expanded and used to hold any needed info
{
    struct sockaddr_in address;         // The socket it contains (IP and port)
    volatile bool      bListen;         // Is this host supposed to be currently listening on a thread 
    socketfd           associatedSocket;// Socket that gets associated with this host.
                                        // This allows the socket from a connection 
                                        // to be saved and reused!
    SSL               *ssl;             // Not NULL if we're connected over SSL

    void (*packet_handler)(char*, uint16_t, struct Host*);
} Host;

BBNETAPI extern Host    *createHost            (const char *ip, 
                                                const uint16_t port);
BBNETAPI extern void     deleteHost            (Host* host);       // Removes a client, closing the socket and freeing the memory
BBNETAPI extern char    *getIP                 (Host* host);       // Returns a string representation of the IP address in the client
BBNETAPI extern void     callHostPacketHandler (char* data, 
                                                uint16_t size, 
                                                Host* host);
BBNETAPI extern void     setHostPacketHandler  (Host* host, 
                                                void (*packet_handler)(char*, uint16_t, Host*));
BBNETAPI extern void     copyHost              (Host* dstHost, 
                                                Host* srcHost);

BBNETAPI extern void   (*getHostPacketHandler  (Host* host)) (char*, uint16_t, Host*);

// Checking or setting an interface for listening
extern void              setCommunicating        (Host* host);        // Sets the bListen boolean
BBNETAPI extern void     closeConnections        (Host* host);        // Unsets the bListen boolean
extern bool              isCommunicating         (const Host* host);
BBNETAPI extern void     setSocket               (Host* host, 
                                                  socketfd sockfd);
BBNETAPI extern socketfd getSocket               (const Host* host);

#endif
