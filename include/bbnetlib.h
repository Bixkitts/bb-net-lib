#ifndef BBNETLIB
#define BBNETLIB

#include <sys/cdefs.h>
#include <netdb.h>

__BEGIN_DECLS

typedef struct Client 
{
    sockaddr_in address; //The socket it contains
    bool bListen = 0;   //Is this client supposed to be currently listening on a thread
} Client;

typedef int socketfd;

extern int sendDataUDP(const char *buffer, const uint16_t bufsize, const socketfd sockfd, const Client *remotehost);    // Sends UDP packets to a specified client
extern int listenForUDP(const char *buffer, const uint16_t bufsize, const Client *localhost, const Client *remotehost);   // Listens for any incoming UDP packets from any client

extern int connectToTCP(const socketfd sockfd, const Client *remotehost);
extern int sendDataTCP(const char *data, const uint16_t datasize, const socketfd sockfd);
extern int listenForTCP(char *buffer, uint16_t bufsize, const socketfd sockfd, Client *localhost, Client *remotehost);   // Listen for a TCP connection

extern Client* createClient(char *ip, u_short port);       // Creates a socket for a particular IP and Port

__END_DECLS

#endif