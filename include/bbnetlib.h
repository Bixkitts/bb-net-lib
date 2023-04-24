#ifndef BBNETLIB
#define BBNETLIB

#include <stdbool.h>
#include <stdint.h>
#include <sys/cdefs.h>
#include <netdb.h>

__BEGIN_DECLS

typedef int socketfd;

typedef struct Client Client;

// UDP Functions
extern int sendDataUDP(const char *buffer, const uint16_t bufsize, Client *remotehost);    
extern int listenForUDP(const char *buffer, const uint16_t bufsize, Client *localhost, Client *remotehost, void (*packet_handler)(char*,uint16_t,Client*));   

//TCP Functions
extern int connectToTCP(Client *remotehost);
extern int sendDataTCP(const char *data, const uint16_t datasize, const Client *remotehost);
extern int listenForTCP(char *buffer, const uint16_t bufsize, Client *localhost, Client *remotehost, void (*packet_handler)(char*,uint16_t,Client*));   


// Use this struct to create a localhost and remotehost.
// The remotehost's IP doesn't matter when listening because
// it gets overidden.
extern Client* createClient(char *ip, uint16_t port);       
extern char* getIP(Client* client); // Returns a string representation of the IP address in the client of INET_ADDRESTRLEN (16)
extern void callClientPacketHandler(char* data, uint16_t size, Client* client);
extern void setClientPacketHandler(Client* client, void (*packet_handler)(char*, uint16_t, Client*));

__END_DECLS

#endif
