#ifndef BBNETLIB
#define BBNETLIB

#include <netdb.h>

struct Client 
{
    sockaddr_in socket; //The socket it contains
    int sockfd;         //file descriptor
    bool bListen = 0;   //Is this client supposed to be currently listening on a thread
};

extern int sendDataUDP(char *buffer, uint16_t bufsize, Client *localhost, Client *remotehost);    // Sends UDP packets to a specified client
extern int listenForUDP(char *buffer, uint16_t bufsize, Client *localhost, Client *remotehost);   // Listens for any incoming UDP packets from any client

extern int listenForTCP(char *buffer, uint16_t bufsize, Client *localhost, Client *remotehost);   // Listen for a TCP connection

Client* createClient(char *ip, u_short port);       // Creates a socket for a particular IP and Port

#endif
