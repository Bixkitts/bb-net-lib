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
extern void enable_tls    (void);

// All connect and send functions.
extern int send_data_udp  (const char *buffer, 
                           const ssize_t bufsize, 
                           struct host* remotehost);
extern int connect_to_tcp (struct host *remotehost);
extern int send_data_tcp  (const char *data, 
                           const ssize_t datasize, 
                           const struct host *remotehost);

// All listening functions.
// The parameters of the packet_handler are:
// pointer to buffer of received data, amount of data in bytes, the host it came from.
extern int listen_for_udp (struct host* localhost, 
                           void (*packet_handler)(char*, ssize_t, struct host*));   
extern int listen_for_tcp (struct host* localhost, 
                           void (*packet_handler)(char*, ssize_t, struct host*));   


// struct host related functions.
// IPs are passed in and out in human readable "X.X.X.X" format.
// IPv6 is not supported yet.
// createHost returns NULL on failure.
extern struct host* create_host  (char *ip, 
                                  uint16_t port);       
extern void         release_host (struct host *host);
// struct host custom attributes can be used to load and store
// a custom pointer in a struct host object
extern void *get_host_custom_attr (struct host* host); 
extern void  set_host_custom_attr (struct host* host,
                                void* ptr); 

// Multicast Functions
extern int  multicast_tcp    (const char *data, 
                              const ssize_t datasize, 
                              int cacheIndex);
extern void cache_host       (struct host* host, 
                              int cacheIndex);
extern void uncache_host     (struct host* host, 
                              int cacheIndex);
extern void clear_host_cache (int cacheIndex);

// IP string is always length 16
extern const char *get_ip           (struct host* host);
extern uint16_t    get_port         (struct host* host);
extern void        close_connection (struct host* host);

__END_DECLS

#endif
