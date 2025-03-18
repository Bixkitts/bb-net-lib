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

// Opaque struct.
// Look in clientObject.c for implementation.
struct host;
struct host_cache;

BBNETAPI extern struct host *create_host(const char *ip, const uint16_t port);
extern void destroy_host(struct host **host);
BBNETAPI extern const char *
get_ip(struct host *host); // Returns a string representation of the IP address
                           // in the client
BBNETAPI extern uint16_t get_port(const struct host *host);
extern void call_host_packet_handler(char *data,
                                     uint16_t size,
                                     struct host *host);
BBNETAPI extern void copy_host(struct host *dst_host, const struct host *src_host);

// Custom attribute stuff
BBNETAPI extern void *get_host_custom_attr(struct host *host);
BBNETAPI extern void set_host_custom_attr(struct host *host, void *ptr);
extern int set_host_non_blocking(struct host *host);
// TLS stuff
// This expects an accepted TLS socket
extern int attempt_tls_handshake(struct host *host, SSL_CTX *sslContext);

// struct host Caching functions
// returns -1 on failure, 0 on success
BBNETAPI extern int cache_host(struct host *host, int cache_index);
BBNETAPI extern void uncache_host(struct host *host, int cache_index);
BBNETAPI extern void clear_host_cache(int cacheIndex);
extern int get_cache_occupancy(int cacheIndex);
extern struct host *get_host_from_cache(int cache_index, int host_index);
extern int get_host_id(const struct host *host);
extern bool is_cached(const struct host *host);
extern const struct sockaddr_in *get_host_addr(const struct host *host);
extern socketfd_t host_accept(struct host *dst_host,
                              const struct host *listening_host);

// Checking or setting an interface for listening
BBNETAPI extern void
close_connections(struct host *host); // Unsets the bListen boolean
                                      //
extern bool is_host_connected(const struct host *host);
extern int create_host_tcp_socket_nb(struct host *host);
extern int host_start_listening_tcp(struct host *host);
extern bool is_host_listening(const struct host *host);
extern ssize_t unencrypted_host_tcp_recv(struct host *remotehost, char *out_buffer, size_t buffer_size);
extern ssize_t encrypted_host_tcp_recv(struct host *remotehost, char *out_buffer, size_t buffer_size);

#endif
