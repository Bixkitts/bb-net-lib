#include <arpa/inet.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <unistd.h>

#include "clientObject.h"
#include "socketsNetLib.h"

struct host {
    char address_string[INET_ADDRSTRLEN];
    struct sockaddr_in address; // The socket it contains (IP and port)
    socklen_t address_len;
    SSL *ssl;                   // Not NULL if we're connected over SSL
    void *custom_attr;      // Library user can store whatever in here
    int id;
    socketfd_t associated_socket; // Socket that gets associated with this host.
                                 // This allows the socket from a connection
                                 // to be saved and reused!
    bool is_listening;  // Is this host supposed to be currently listening on a thread

    // Flags I should compress if I have too many
    bool is_cached;  // If the host has been cached,
                    // it should not be freed until
                    // the cache is destroyed.
    bool is_waiting; // This host has a non-blocking socket
                    // that's waiting to call send/recv again
};
static pthread_mutex_t cache_lock[MAX_HOST_CACHES] = {
    PTHREAD_MUTEX_INITIALIZER};

static struct host *host_cache[MAX_HOST_CACHES][MAX_HOSTS_PER_CACHE] = {0};

static atomic_int host_id_counter = ATOMIC_VAR_INIT(0);

static int get_free_cache_spot(int cache_index);
static void remove_host_at_cache_index(int cache_index, int host_index);

struct host *create_host(const char *ip, const uint16_t port)
{
    // TODO: custom allocator
    struct host *host = NULL;
    host = calloc(1, sizeof(*host));
    if (!host) {
        perror(err_strings[STR_ERROR_MALLOC]);
        return NULL;
    }
    // filling in the data of the host's ip.
    strcpy(host->address_string, ip);
    host->id                 = atomic_fetch_add(&host_id_counter, 1);
    host->address.sin_family = AF_INET;
    host->address.sin_port   = htons(port);

    inet_pton(AF_INET, ip, &host->address.sin_addr);
    return host;
}

void copy_host(struct host *dstHost, const struct host *srcHost)
{
    memcpy(dstHost, srcHost, sizeof(struct host));
}

void *get_host_custom_attr(struct host *host)
{
    return host->custom_attr;
}

void set_host_custom_attr(struct host *host, void *ptr)
{
    host->custom_attr = ptr;
}
bool is_cached(const struct host *host)
{
    return host->is_cached;
}
static int get_free_cache_spot(int cacheIndex)
{
    for (int i = 0; i < MAX_HOSTS_PER_CACHE; i++) {
        if (host_cache[cacheIndex][i] == NULL) {
            return i;
        }
    }
    return -1;
}
static void remove_host_at_cache_index(int cacheIndex, int hostIndex)
{
    struct host *host = host_cache[cacheIndex][hostIndex];
    if (host != NULL) {
        host->is_cached                   = 0;
        host_cache[cacheIndex][hostIndex] = NULL;
    }
}

const struct sockaddr_in *get_host_addr(const struct host *host)
{
    return &host->address;
}
void cache_host(struct host *host, int cacheIndex)
{
    pthread_mutex_lock(&cache_lock[cacheIndex]);

    if (cacheIndex >= MAX_HOST_CACHES) {
        fprintf(stderr, "\n%s", err_strings[STR_ERROR_HOST_CACHE_INDEX]);
        goto unlock;
    }
    int spot = get_free_cache_spot(cacheIndex);
    if (spot != -1) {
        host_cache[cacheIndex][spot] = host;
        host->is_cached               = 1;
    }
    else {
        fprintf(stderr, "\nHost cache full, can't add host %s", get_ip(host));
    }
unlock:
    pthread_mutex_unlock(&cache_lock[cacheIndex]);
}

void uncache_host(struct host *host, int cacheIndex)
{
    pthread_mutex_lock(&cache_lock[cacheIndex]);
    for (int i = 0; i < MAX_HOSTS_PER_CACHE; i++) {
        if (host == get_host_from_cache(cacheIndex, i)) {
            remove_host_at_cache_index(cacheIndex, i);
            break;
        }
    }
    pthread_mutex_unlock(&cache_lock[cacheIndex]);
}

void clear_host_cache(int cacheIndex)
{
    pthread_mutex_lock(&cache_lock[cacheIndex]);
    if (cacheIndex >= MAX_HOST_CACHES) {
        fprintf(stderr, "\n%s", err_strings[STR_ERROR_HOST_CACHE_INDEX]);
        goto unlock;
    }
    for (int i = 0; i < MAX_HOSTS_PER_CACHE; i++) {
        remove_host_at_cache_index(cacheIndex, i);
    }
unlock:
    pthread_mutex_unlock(&cache_lock[cacheIndex]);
}
struct host *get_host_from_cache(int cacheIndex, int hostIndex)
{
    return host_cache[cacheIndex][hostIndex];
}
const char *get_ip(struct host *host)
{
    return (const char *)host->address_string;
}
uint16_t get_port(const struct host *host)
{
    return ntohs(host->address.sin_port);
}
int get_host_id(const struct host *host)
{
    return host->id;
}

void destroy_host(struct host **host)
{
    if (!(*host)) {
        return;
    }
    if ((*host)->is_cached == 1) {
        return;
    }
    if ((*host)->ssl) {
        int shutdown_result;
        do {
            shutdown_result = SSL_shutdown((*host)->ssl);
        } while (shutdown_result == 0);
        if (shutdown_result < 0) {
            // Handle error if necessary
        }
        SSL_free((*host)->ssl);
    }
    close((*host)->associated_socket);
    free(*host);
    *host = NULL;
}

int attempt_tls_handshake(struct host *host, SSL_CTX *ssl_context)
{
    host->ssl = SSL_new(ssl_context);
    SSL_set_fd(host->ssl, host->associated_socket);
    int ssl_accept_result = 0;

    while (ssl_accept_result <= 0) {
        ssl_accept_result = SSL_accept(host->ssl);
        if (ssl_accept_result <= 0) {
            int ssl_error = SSL_get_error(host->ssl, ssl_accept_result);
            if (ssl_error == SSL_ERROR_WANT_READ ||
                ssl_error == SSL_ERROR_WANT_WRITE) {
                continue;
            }
            ERR_print_errors_fp(stderr);
            return -1;
        }
    }
    return 0;
}

void close_connections(struct host *host)
{
    host->is_listening = 0;
}

void set_communicating(struct host *host)
{
    host->is_listening = 1;
}

int bind_host_socket(struct host *host)
{
    struct sockaddr *bound_address = (struct sockaddr *)&host->address;
    if (FAILURE(bind(host->associated_socket, bound_address, sizeof(host->address)))) {
        perror("Failed to bind socket!\n");
        return ERROR;
    }
    return SUCCESS;
}

int set_host_non_blocking(struct host *host)
{
    const socketfd_t target_socket = host->associated_socket;
    int flags = fcntl(target_socket, F_GETFL, 0);
    if (flags == -1) {
        return ERROR;
    }
    if (fcntl(target_socket, F_SETFL, flags | O_NONBLOCK) == -1) {
        perror("Error setting socket to non-blocking mode");
        return ERROR;
    }
    return SUCCESS;
}

// Returns -1 on error.
int host_accept(struct host *dst_host,
                const struct host *listening_host)
{
    dst_host->address_len = sizeof(struct sockaddr);
    socketfd_t sock = accept(listening_host->associated_socket,
                             (struct sockaddr *)&dst_host->address,
                             &dst_host->address_len);
    if (0 > sock) {
        return -1;
    }
    return dst_host->associated_socket = sock;
}

bool is_communicating(const struct host *host)
{
    return host->is_listening;
}

void set_socket(struct host *restrict host, socketfd_t sockfd)
{
    host->associated_socket = sockfd;
}

socketfd_t get_socket(const struct host *host)
{
    return host->associated_socket;
}

SSL *get_host_ssl(const struct host *restrict host)
{
    return host->ssl;
}
