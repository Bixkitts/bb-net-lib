#ifndef hostOBJECT
#define hostOBJECT

#include <arpa/inet.h>
#include <netinet/in.h>
#include <openssl/ssl.h>
#include <stdbool.h>
#include <sys/socket.h>

#include "defines.h"
#include "socketfd.h"

#define MAX_HOST_CACHES     16
#define MAX_HOSTS_PER_CACHE 1024
#define MAX_HOSTS           2048

struct host {
    char addressStr[INET_ADDRSTRLEN];
    struct sockaddr_in address; // The socket it contains (IP and port)
    SSL *ssl;                   // Not NULL if we're connected over SSL
    void *customAttribute;      // library user can store whatever in here
    int id;
    socketfd_t associatedSocket; // Socket that gets associated with this host.
                                 // This allows the socket from a connection
                                 // to be saved and reused!
    bool bListen; // Is this host supposed to be currently listening on a thread
    // Flags I should compress if I have too many
    bool isCached;  // If the host has been cached,
                    // it should not be freed until
                    // the cache is destroyed.
    bool isWaiting; // This host has a non-blocking socket
                    // that's waiting to call send/recv again
};

BBNETAPI extern struct host *create_host(const char *ip, const uint16_t port);
extern void destroy_host(struct host **host);
BBNETAPI extern const char *
get_ip(struct host *host); // Returns a string representation of the IP address
                           // in the client
BBNETAPI extern uint16_t get_port(struct host *host);
extern void call_host_packet_handler(char *data,
                                     uint16_t size,
                                     struct host *host);
BBNETAPI extern void copy_host(struct host *dstHost, struct host *srcHost);

// Custom attribute stuff
BBNETAPI extern void *get_host_custom_attr(struct host *host);
BBNETAPI extern void set_host_custom_attr(struct host *host, void *ptr);
// TLS stuff
// This expects an accepted TLS socket
extern int attempt_tls_handshake(struct host *host, SSL_CTX *sslContext);
extern SSL *get_host_ssl(const struct host *restrict host);

// struct host Caching functions
BBNETAPI extern void cache_host(struct host *host, int cacheIndex);
BBNETAPI extern void uncache_host(struct host *host, int cacheIndex);
BBNETAPI extern void clear_host_cache(int cacheIndex);
extern const int get_cache_occupancy(int cacheIndex);
extern struct host *get_host_from_cache(int cacheIndex, int hostIndex);
extern int get_host_id(struct host *host);
extern bool is_cached(struct host *host);

// Checking or setting an interface for listening
extern void set_communicating(struct host *host); // Sets the bListen boolean
BBNETAPI extern void
close_connections(struct host *host); // Unsets the bListen boolean
extern bool is_communicating(const struct host *host);
extern void set_socket(struct host *host, socketfd_t sockfd);
extern socketfd_t get_socket(const struct host *host);

#endif
