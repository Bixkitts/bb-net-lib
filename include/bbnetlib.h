#ifndef BBNETLIB
#define BBNETLIB

#include <stdbool.h>
#include <stdint.h>
#include <sys/cdefs.h>
#include <netdb.h>

__BEGIN_DECLS

typedef int socketfd_t;
struct host;

// All configuration functions.
// Call these before any of the others!
extern void enableTLS    ();

// All connect and send functions.
extern int sendDataUDP   (const char *buffer, 
                          const ssize_t bufsize, 
                          struct host* remotehost);
extern int connectToTCP  (struct host *remotehost);
extern int sendDataTCP   (const char *data, 
                          const ssize_t datasize, 
                          const struct host *remotehost);

// All listening functions.
// The parameters of the packet_handler are:
// pointer to buffer of received data, amount of data in bytes, the host it came from.
extern int listenForUDP  (struct host* localhost, 
                          void (*packet_handler)(char*, ssize_t, struct host*));   
extern int listenForTCP  (struct host* localhost, 
                          void (*packet_handler)(char*, ssize_t, struct host*));   


// struct host related functions.
// IPs are passed in and out in human readable "X.X.X.X" format.
// IPv6 is not supported yet.
// createHost returns NULL on failure.
extern struct host*  createHost        (char *ip, 
                                uint16_t port);       
extern void  destroyHost       (struct host *host);
// struct host custom attributes can be used to load and store
// a custom pointer in a struct host object
extern void *getHostCustomAttr (struct host* host); 
extern void  setHostCustomAttr (struct host* host,
                                void* ptr); 

// Multicast Functions
int  multicastTCP   (const char *data, 
                     const ssize_t datasize, 
                     int cacheIndex);
void cacheHost      (struct host* host, 
                     int cacheIndex);
void uncacheHost    (struct host* host, 
                     int cacheIndex);
void clearHostCache (int cacheIndex);

// IP string is always length 16
extern const char *getIP            (struct host* host);
extern uint16_t    getPort          (struct host* host);
extern void        closeConnections (struct host* host);

__END_DECLS

#endif
