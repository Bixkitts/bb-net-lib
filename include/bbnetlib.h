#ifndef BBNETLIB
#define BBNETLIB

#include <sys/cdefs.h>
#include <netdb.h>

__BEGIN_DECLS

typedef int socketfd;

typedef struct Client 
{
    struct sockaddr_in address; //The socket it contains
    volatile bool bListen;   //Is this client supposed to be currently listening on a thread
    socketfd associatedSocket;
} Client;


extern int sendDataUDP(const char *buffer, const uint16_t bufsize, Client *remotehost);    // Sends UDP packets to a specified client
extern int listenForUDP(const char *buffer, const uint16_t bufsize, Client *localhost, Client *remotehost);   // Listens for any incoming UDP packets from any client

extern int connectToTCP(Client *remotehost);
extern int sendDataTCP(const char *data, const uint16_t datasize, const Client *remotehost);
extern int listenForTCP(char *buffer, const uint16_t bufsize, Client *localhost, const Client *remotehost);   // Listen for a TCP connection
int receiveTCPpackets(char *buffer, const uint16_t bufsize, const socketfd sockfd, const Client *localhost); 

extern Client* createClient(char *ip, u_short port);       // Creates a socket for a particular IP and Port

__END_DECLS

#endif
