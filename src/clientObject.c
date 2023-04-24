#include <netinet/in.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <strings.h>
#include <unistd.h>

#include "clientObject.h"

Client* createClient(const char *ip, const uint16_t port)
{
    Client* client;
    client = (struct Client*) malloc(sizeof(struct Client));
    unsetListening(client);
    
    bzero((char *) &client->address, sizeof(client->address));

    //filling in the data of the client's ip.
    client->address.sin_family = AF_INET;
    client->address.sin_port = htons(port);
    inet_pton(AF_INET, ip, &client->address.sin_addr);
    
    setClientPacketHandler(client, NULL);

    return client;
}
char* getIP(Client* client)
{
    char* ip_str = (char*) malloc(INET_ADDRSTRLEN * sizeof(char));
    inet_ntop(AF_INET, &(client->address.sin_addr), ip_str, INET_ADDRSTRLEN);
    return ip_str;
}
void removeClient(Client* client)
{
    free(client);
}

void unsetListening(Client* client)
{
    client->bListen = 0;
}

void setListening(Client* client)
{
    client->bListen = 1;
}

bool isListening(const Client* client)
{
    return client->bListen;
}

void setSocket(Client* client, socketfd sockfd)
{
    client->associatedSocket = sockfd;
}

socketfd getSocket(const Client* client)
{
    return client->associatedSocket;
}

void callClientPacketHandler(char* data, uint16_t size, Client* client)
{
    (*client->packet_handler)(data, size, client);
}

void setClientPacketHandler(Client* client, void (*packet_handler)(char*, uint16_t, Client*))
{
    client->packet_handler = packet_handler;
}

void (*getClientPacketHandler(Client* client))(char*, uint16_t, Client*)
{
    return client->packet_handler;
}
