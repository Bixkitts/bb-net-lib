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
    int listenForData(char *buffer, uint16_t bufsize, Client &localhost, Client &remotehost)    //Should be called on it's own thread as the while loop is blocking 
    //need to implement client recognition by comparing the IP of incoming packets
    {                                                                    
        localhost.bListen = 1;
        int n;
        socklen_t len = sizeof(localhost.Socket);

        n = recvfrom(localhost.sockfd, buffer, bufsize, MSG_WAITALL, ( struct sockaddr *)&localhost.Socket, &len);

        while(localhost.bListen == 1)
        {
            n = recvfrom(localhost.sockfd, buffer, bufsize, MSG_WAITALL, ( struct sockaddr *)&localhost.Socket, &len);
            buffer[n] = '\0';
        }

        return 0;
    }

    void stopListen(Client &client)
    {
        client.bListen = 0;
    }
}
