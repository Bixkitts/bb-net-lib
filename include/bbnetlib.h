#ifndef BBNETLIB
#define BBNETLIB

#include <stdbool.h>
#include <stdint.h>
#include <sys/cdefs.h>
#include <netdb.h>

__BEGIN_DECLS

typedef int    socketfd;
typedef struct Host_Internal *Host;

// All connect and send functions.
extern int sendDataUDP   (const char *buffer, 
                          const ssize_t bufsize, 
                          Host remotehost);
extern int connectToTCP  (Host remotehost);
extern int sendDataTCP   (const char *data, 
                          const ssize_t datasize, 
                          const Host remotehost);

// All listening functions.
// The parameters of the packet_handler are:
// pointer to buffer of received data, amount of data in bytes, the host it came from.
extern int listenForUDP  (Host localhost, 
                          void (*packet_handler)(char*, ssize_t, Host));   
extern int listenForTCP  (Host localhost, 
                          void (*packet_handler)(char*, ssize_t, Host));   


// Host related functions.
// IPs are passed in and out in human readable "X.X.X.X" format.
// IPv6 is not supported yet.
// createHost returns NULL on failure.
extern Host  createHost        (char *ip, 
                                uint16_t port);       
extern void  destroyHost       (Host *host);
// Host custom attributes can be used to load and store
// a custom pointer in a Host object
extern void *getHostCustomAttr (Host host); 
extern void  setHostCustomAttr (Host host,
                                void* ptr); 

// IP string is always length 16
extern const char *getIP            (Host host);
extern uint16_t    getPort          (Host host);
extern void        closeConnections (Host host);

__END_DECLS

#endif
