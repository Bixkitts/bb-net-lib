#ifndef hostOBJECT
#define hostOBJECT

#include <arpa/inet.h>
#include <netinet/in.h>
#include <openssl/ssl.h>
#include <stdbool.h>
#include <sys/socket.h>

#include "defines.h"
#include "socketfd.h"
#include "socketsNetLib.h"

#define MAX_HOST_CACHES     16
#define MAX_HOSTS_PER_CACHE 1024
#define MAX_HOSTS           2048

// Opaque struct.
// Look in clientObject.c for implementation.
struct host;

BBNETAPI struct host *create_host(const char *ip, const uint16_t port);
void release_host(struct host **host);
BBNETAPI const char *
get_ip(struct host *host); // Returns a string representation of the IP address
                           // in the client
BBNETAPI uint16_t get_port(const struct host *host);
void call_host_packet_handler(char *data,
                                     uint16_t size,
                                     struct host *host);
BBNETAPI void copy_host(struct host *dst_host, const struct host *src_host);

// Custom attribute stuff
BBNETAPI void *get_host_custom_attr(struct host *host);
BBNETAPI void set_host_custom_attr(struct host *host, void *ptr);
int set_host_non_blocking(struct host *host);
// TLS stuff
// This expects an accepted TLS socket
int attempt_tls_handshake(struct host *host, SSL_CTX *sslContext);
const struct sockaddr_in *get_host_addr(const struct host *host);
socketfd_t host_accept(struct host *dst_host,
                              const struct host *listening_host);

// Checking or setting an interface for listening
BBNETAPI void
close_connection(struct host *host); // Unsets the bListen boolean
                                      //
ssize_t send_tcp_encrypted_internal(const struct host *remotehost,
                                          const char *data,
                                          ssize_t data_size);
ssize_t send_tcp_unencrypted_internal(const struct host *remotehost,
                                            const char *data,
                                            ssize_t data_size);
bool is_host_connected(const struct host *host);
int create_host_tcp_socket_nb(struct host *host);
int host_start_listening_tcp(struct host *host);
bool is_host_listening(const struct host *host);
ssize_t unencrypted_host_tcp_recv(struct host *remotehost, char *out_buffer, size_t buffer_size);
ssize_t encrypted_host_tcp_recv(struct host *remotehost, char *out_buffer, size_t buffer_size);
int host_socket_select(struct host *host);
int connect_to_tcp_internal(struct host *remotehost);
int multicast_tcp_internal(const char *data,
                           const ssize_t datasize,
                           int cache_index,
                           ssize_t (*send_func)(const char *data,
                                                const ssize_t datasize,
                                                struct host *remotehost));
int add_host_socket_to_epoll(struct host *host, struct socket_epoller *epoller);

// struct host Caching functions
// --------------------------------------------
// returns -1 on failure, 0 on success
BBNETAPI int cache_host(struct host *host, int cache_index);
BBNETAPI void uncache_host(struct host *host, int cache_index);
BBNETAPI void clear_host_cache(int cache_index);

// --------------------------------------------
#endif
