#ifndef hostOBJECT
#define hostOBJECT

#include <netinet/in.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>

#include "defines.h"
#include "socketfd.h"

#define MAX_HOST_CACHES     16
#define MAX_HOSTS_PER_CACHE 1024
#define MAX_HOSTS           2048


struct host 
{
    char               addressStr[INET_ADDRSTRLEN];
    struct sockaddr_in address;         // The socket it contains (IP and port)
    SSL               *ssl;             // Not NULL if we're connected over SSL
    void              *customAttribute; // library user can store whatever in here
    int                id;
    socketfd_t           associatedSocket;// Socket that gets associated with this host.
                                        // This allows the socket from a connection 
                                        // to be saved and reused!
    bool               bListen;         // Is this host supposed to be currently listening on a thread 
    // Flags I should compress if I have too many
    bool               isCached;        // If the host has been cached,
                                        // it should not be freed until
                                        // the cache is destroyed.
    bool               isWaiting;       // This host has a non-blocking socket
                                        // that's waiting to call send/recv again
};

BBNETAPI extern struct host        *createHost            (const char *ip, 
                                                    const uint16_t port);
extern void                  destroyHost           (struct host **host);
BBNETAPI extern const char  *getIP                 (struct host* host);       // Returns a string representation of the IP address in the client
BBNETAPI extern uint16_t     getPort               (struct host* host);
extern void                  callHostPacketHandler (char* data, 
                                                    uint16_t size, 
                                                    struct host* host);
BBNETAPI extern void         copyHost              (struct host* dstHost, 
                                                    struct host* srcHost);

// Custom attribute stuff
BBNETAPI extern void        *getHostCustomAttr     (struct host* host); 
BBNETAPI extern void         setHostCustomAttr     (struct host* host,
                                                    void* ptr); 
// TLS stuff
// This expects an accepted TLS socket
extern int                   attemptTLSHandshake   (struct host* host, 
                                                    SSL_CTX *sslContext);
extern SSL                  *getHostSSL            (const struct host *restrict host);

// struct host Caching functions
BBNETAPI extern void         cacheHost             (struct host* host, 
                                                    int cacheIndex);
BBNETAPI extern void         uncacheHost           (struct host* host, 
                                                    int cacheIndex);
BBNETAPI extern void         clearHostCache        (int cacheIndex);
extern const int             getCacheOccupancy     (int cacheIndex);
extern struct host                 *getHostFromCache      (int cacheIndex,
                                                    int hostIndex);
extern int                   getHostID             (struct host *host);
extern bool                  isCached              (struct host* host);

// Checking or setting an interface for listening
extern void                  setCommunicating      (struct host* host);        // Sets the bListen boolean
BBNETAPI extern void         closeConnections      (struct host* host);        // Unsets the bListen boolean
extern bool                  isCommunicating       (const struct host* host);
extern void                  setSocket             (struct host* host, 
                                                    socketfd_t sockfd);
extern socketfd_t              getSocket             (const struct host* host);

#endif
