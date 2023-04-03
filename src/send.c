#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <strings.h>
#include <unistd.h>
#include "clientObject.h"

int sendDataUDP(char *data, uint16_t datasize, Client client)
{
    socklen_t len = sizeof(client.socket);    
    
    sendto(client.sockfd, data, datasize, MSG_CONFIRM, 
        (const struct sockaddr *) &client.socket, len);
    
    return 0;
}
