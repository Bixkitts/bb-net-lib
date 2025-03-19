#include <arpa/inet.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <errno.h>
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
    void *custom_attr;          // Library user can store whatever in here
    socketfd_t associated_socket; // Socket that gets associated with this host.
                                  // This allows the socket from a connection
                                  // to be saved and reused!
    bool is_listening;  // Is this host supposed to be currently listening on a thread
    bool is_connected;  // Is a part of an ongoing connection

    bool is_cached;  // If the host has been cached,
                     // it should not be freed
                     // until it is not cached

    bool is_waiting; // This host has a non-blocking socket
                     // that's waiting to call send/recv again
};

struct host_cache {
    pthread_mutex_t lock;
    // We do not lock the entire host cache
    atomic_bool occupancy[MAX_HOSTS_PER_CACHE];
    struct host *hosts[MAX_HOSTS_PER_CACHE];
};

static struct host_cache host_caches[MAX_HOST_CACHES] = {0};

static int get_free_cache_spot(int cache_index);
static int host_socket_select(struct host *host);

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
    host->address.sin_family = AF_INET;
    host->address.sin_port   = htons(port);

    inet_pton(AF_INET, ip, &host->address.sin_addr);
    return host;
}

void copy_host(struct host *dst_host, const struct host *src_host)
{
    memcpy(dst_host, src_host, sizeof(struct host));
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

// TODO: Check atomic flags!!
static int get_free_cache_spot(int cache_index)
{
    for (int i = 0; i < MAX_HOSTS_PER_CACHE; i++) {
        bool expected = 0;
        if (atomic_compare_exchange_strong(&(host_caches[cache_index].occupancy[i]), &expected, 1)) {
            return i;
        }
    }
    return -1;
}

const struct sockaddr_in *get_host_addr(const struct host *host)
{
    return &host->address;
}
int cache_host(struct host *host, int cache_index)
{

    if (cache_index >= MAX_HOST_CACHES) {
        fprintf(stderr, "\n%s", err_strings[STR_ERROR_HOST_CACHE_INDEX]);
        goto unlock;
    }
    int spot = get_free_cache_spot(cache_index);
    if (spot != -1) {
        host_cache[cacheIndex][spot] = host;
        host->is_cached               = 1;
    }
    else {
        fprintf(stderr, "\nHost cache full, can't add host %s", get_ip(host));
    }
}

// Should return a host pointer for deletion etc......
void uncache_host(struct host *host, int cache_index)
{
    for (int i = 0; i < MAX_HOSTS_PER_CACHE; i++) {
        if (host == host_caches[cache_index].hosts[i]) {
            host_caches[cache_index].hosts[i] = NULL;
            atomic_exchange(&host_caches[cache_index].occupancy[i], 0);
        }
    }
}

void clear_host_cache(int cacheIndex)
{
    pthread_mutex_lock(&cache_occupancy[cacheIndex]);
    if (cacheIndex >= MAX_HOST_CACHES) {
        fprintf(stderr, "\n%s", err_strings[STR_ERROR_HOST_CACHE_INDEX]);
        goto unlock;
    }
    for (int i = 0; i < MAX_HOSTS_PER_CACHE; i++) {
        uncache_host(cacheIndex, i);
    }
unlock:
    pthread_mutex_unlock(&cache_occupancy[cacheIndex]);
}

struct host *get_host_from_cache(int cache_index, int host_index)
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

void close_connection(struct host *host)
{
    host->is_connected = 0;
    close(host->associated_socket);
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

// Returns -1 on error or 0 on success
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
    dst_host->is_connected = 1;
    dst_host->associated_socket = sock;
    return 0;
}

bool is_host_connected(const struct host *host)
{
    return host->is_connected;
}


// returns -1 on error and 0 on success
int create_host_tcp_socket_nb(struct host *host)
{
    host->associated_socket = create_socket(SOCK_DEFAULT_TCP);
    if (host->associated_socket < 0) {
        return -1;
    }
    set_host_non_blocking(host);
    return 0;
}

// returns 0 on success, nonzero on failure
int host_start_listening_tcp(struct host *host)
{
    int er = 0;
    if (0 >= host->associated_socket) {
        er = create_host_tcp_socket_nb(host);
        if (er) return ERROR;
    }
    if (FAILURE(bind_host_socket(host))) {
        perror("Failed to bind listen socket.\n");
        return ERROR;
    }
    if (FAILURE(listen(host->associated_socket, SOCK_BACKLOG))) {
        fprintf(stderr,
                "\nError: listen() failed with errno %d: %s\n",
                errno,
                strerror(errno));
        return ERROR;
    }
    host->is_listening = 1;
    return 0;
}

bool is_host_listening(const struct host *host)
{
    return host->is_listening;
}
ssize_t unencrypted_host_tcp_recv(struct host *remotehost, char *out_buffer, size_t buffer_size)
{
    return recv(remotehost->associated_socket, out_buffer, buffer_size, 0);
}
ssize_t encrypted_host_tcp_recv(struct host *remotehost,
                                       char *out_buffer,
                                       size_t buffer_size)
{
    return (ssize_t)SSL_read(remotehost->ssl,
                             out_buffer,
                             buffer_size);
}
ssize_t send_to_host_tcp_unencrypted(const struct host *remotehost,
                                     const char *data,
                                     ssize_t data_size)
{
    return (ssize_t)send(remotehost->associated_socket,
                         data,
                         data_size,
                         0);
}
ssize_t send_to_host_tcp_encrypted(const struct host *remotehost,
                                   const char *data,
                                   ssize_t data_size)
{
    return SSL_write(remotehost->ssl,
                     data,
                     data_size);
}

// returns -1 on error, 1 on ready socket, 0 on socket not ready
static int host_socket_select(struct host *host)
{
    fd_set writefds;
    FD_ZERO(&writefds);
    FD_SET(host->associated_socket, &writefds);
    int select_status = select(host->associated_socket + 1,
                               NULL,
                               &writefds,
                               NULL,
                               NULL);
    if (0 > select_status) {
        perror("Select error");
        return -1;
    }
    return select_status > 0;
}
