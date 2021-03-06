// A header file do declare and define a structure for a connected client and interface with them

#include <iostream>
#include <sys/types.h>
#include <strings.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
namespace netlib
{
    struct Client 
    {
        sockaddr_in Socket; //The socket it contains
        int sockfd;         //file descriptor
        bool bListen = 0;   //Is this client supposed to be currently listening on a thread
    };
}
