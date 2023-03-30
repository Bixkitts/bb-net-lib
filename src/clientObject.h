// A header file do declare and define a structure for a connected client and interface with them

#include <stdbool.h>
#include <sys/types.h>
#include <strings.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
typedef struct Client 
{
        struct sockaddr_in Socket;  // The socket it contains 
        int sockfd;                 // file descriptor 
        bool bListen;               // Is this client supposed to be currently listening on a thread 
} Client;
