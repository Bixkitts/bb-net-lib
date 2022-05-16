#include <iostream>
#include <sys/types.h>
#include <strings.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include "clientObject.h"

namespace netlib
{

    int listenForData(char *buffer, uint16_t bufsize, Client &client)    //Should be called on it's own thread as the while loop is blocking 
    {
        client.bListen = 1;
        int n;
        socklen_t len = sizeof(client.Socket);
        while(client.bListen == 1)
        {
            n = recvfrom(client.sockfd, buffer, bufsize, MSG_WAITALL, ( struct sockaddr *)&client.Socket, &len);
            buffer[n] = '\0';
        }

        return 0;
    }

    void stopListen(Client &client)
    {
        client.bListen = 0;
    }
}
