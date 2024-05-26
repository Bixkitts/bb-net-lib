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


typedef struct Host 
{
    char               addressStr[INET_ADDRSTRLEN];
    struct sockaddr_in address;         // The socket it contains (IP and port)
    SSL               *ssl;             // Not NULL if we're connected over SSL
    void              *customAttribute; // library user can store whatever in here
    int                id;
    socketfd           associatedSocket;// Socket that gets associated with this host.
                                        // This allows the socket from a connection 
                                        // to be saved and reused!
    bool               bListen;         // Is this host supposed to be currently listening on a thread 
    // Flags I should compress if I have too many
    bool               isCached;        // If the host has been cached,
                                        // it should not be freed until
                                        // the cache is destroyed.
    bool               isWaiting;       // This host has a non-blocking socket
                                        // that's waiting to call send/recv again
} Host;

BBNETAPI extern Host        *createHost            (const char *ip, 
                                                    const uint16_t port);
extern void                  destroyHost           (Host **host);
BBNETAPI extern const char  *getIP                 (Host* host);       // Returns a string representation of the IP address in the client
BBNETAPI extern uint16_t     getPort               (Host* host);
extern void                  callHostPacketHandler (char* data, 
                                                    uint16_t size, 
                                                    Host* host);
BBNETAPI extern void         copyHost              (Host* dstHost, 
                                                    Host* srcHost);

// Custom attribute stuff
BBNETAPI extern void        *getHostCustomAttr     (Host* host); 
BBNETAPI extern void         setHostCustomAttr     (Host* host,
                                                    void* ptr); 
// TLS stuff
// This expects an accepted TLS socket
extern int                   attemptTLSHandshake   (Host* host, 
                                                    SSL_CTX *sslContext);
extern SSL                  *getHostSSL            (const Host *restrict host);

// Host Caching functions
BBNETAPI extern void         cacheHost             (Host* host, 
                                                    int cacheIndex);
BBNETAPI extern void         uncacheHost           (Host* host, 
                                                    int cacheIndex);
BBNETAPI extern void         clearHostCache        (int cacheIndex);
extern const int             getCacheOccupancy     (int cacheIndex);
extern Host                 *getHostFromCache      (int cacheIndex,
                                                    int hostIndex);
extern int                   getHostID             (Host *host);
extern bool                  isCached              (Host* host);

// Checking or setting an interface for listening
extern void                  setCommunicating      (Host* host);        // Sets the bListen boolean
BBNETAPI extern void         closeConnections      (Host* host);        // Unsets the bListen boolean
extern bool                  isCommunicating       (const Host* host);
extern void                  setSocket             (Host* host, 
                                                    socketfd sockfd);
extern socketfd              getSocket             (const Host* host);

#endif
