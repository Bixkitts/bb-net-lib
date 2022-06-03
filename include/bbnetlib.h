#ifndef BBNETLIB
#define BBNETLIB
#include <iostream>
#include <netdb.h>
namespace netlib
{
    struct Client 
    {
        sockaddr_in Socket; //The socket it contains
        int sockfd;         //file descriptor
        bool bListen = 0;   //Is this client supposed to be currently listening on a thread
    };    

    int sendData(char *data, uint16_t datasize);
    int listenForData(char *buffer, uint16_t bufsize);
    Client* createClient(char *ip, u_short port);
}
#endif
