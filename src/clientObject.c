#include <arpa/inet.h>
#include <assert.h>
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
    socketfd_t socket; // Socket that gets associated with this host.
                                  // This allows the socket from a connection
                                  // to be saved and reused!
    atomic_int reference_count; // References held by threads and host_caches.
                                // On 0, the host can be deleted.
    bool is_listening;  // Is this host supposed to be currently listening on a thread
    bool is_connected;  // Is a part of an ongoing connection

    bool is_waiting; // This host has a non-blocking socket
                     // that's waiting to call send/recv again
};

// cache that stores hosts
struct host_cache {
    struct host *hosts[MAX_HOSTS_PER_CACHE];
    pthread_rwlock_t rwlock;
};

static struct host_cache host_caches[MAX_HOST_CACHES] = {0};

static int get_free_cache_spot(const struct host_cache *cache);
static void uncache_host_internal(struct host_cache *cache, int host_index);
static int bind_host_socket(struct host *host);

struct host *create_host(const char *ip, const uint16_t port)
{
    assert(ip);
    // TODO: custom allocator
    struct host *host = NULL;
    host = calloc(1, sizeof(*host));
    if (!host) {
        perror(err_strings[STR_ERROR_MALLOC]);
        return NULL;
    }
    atomic_init(&host->reference_count, 1);
    strcpy(host->address_string, ip);
    host->address.sin_family = AF_INET;
    host->address.sin_port   = htons(port);

    inet_pton(AF_INET, ip, &host->address.sin_addr);
    return host;
}

void copy_host(struct host *dst_host, const struct host *src_host)
{
    assert(dst_host && src_host);
    memcpy(dst_host, src_host, sizeof(struct host));
}

void *get_host_custom_attr(struct host *host)
{
    // We have no reason to be fetching a NULL custom attribute,
    // this is a programming mistake by the client.
    // Call set_host_custom_attr() before get_host_custom_attr().
    assert(host && host->custom_attr);
    return host->custom_attr;
}

void set_host_custom_attr(struct host *host, void *ptr)
{
    assert(host);
    host->custom_attr = ptr;
}

// Caller locks the cache
static int get_free_cache_spot(const struct host_cache *cache)
{
    assert(cache);
    int res = -1;
    for (int i = 0; i < MAX_HOSTS_PER_CACHE; i++) {
        if (!cache->hosts[i]) {
            res = i;
            break;
        }
    }
    return res;
}

const struct sockaddr_in *get_host_addr(const struct host *host)
{
    assert(host);
    return &host->address;
}

// Increases the reference count
// on a host and returns 1 on success
static bool acquire_host(struct host *host)
{
    assert(host);
    int ref = atomic_fetch_add(&host->reference_count, 1);
    if (ref < 1) return 0; // Host has been deleted, failed to acquire despite having a pointer
    return 1;
}

int connect_to_tcp_internal(struct host *remotehost)
{
    const socketfd_t sockfd = create_socket(SOCK_DEFAULT_TCP);
    const struct sockaddr *remote_address =
        (const struct sockaddr *)get_host_addr(remotehost);
    const socklen_t size_of_address = sizeof(*remote_address);
    if (FAILURE(connect(sockfd, remote_address, size_of_address))) {
        close(sockfd);
        perror("Connect failed\n");
        return ERROR;
    }
    remotehost->socket = sockfd;
    return SUCCESS;
}

// Returns the index in the cache the host got stored at,
// or -1 on failure.
// Increments the reference in the host.
int cache_host(struct host *host, int cache_index)
{
    assert(cache_index < MAX_HOST_CACHES);
    struct host_cache *cache = &host_caches[cache_index];
    pthread_rwlock_wrlock(&cache->rwlock);
    int spot = get_free_cache_spot(cache);
    if (spot != -1) {
        if(acquire_host(host)) {
            cache->hosts[spot] = host;
        }
    }
    else {
        fprintf(stderr, "Host cache full, can't add host %s\n", get_ip(host));
    }
    pthread_rwlock_unlock(&host_caches[cache_index].rwlock);
    return spot;
}

static void uncache_host_internal(struct host_cache *cache, int host_index)
{
    assert(cache && host_index < MAX_HOSTS_PER_CACHE);
    release_host(&cache->hosts[host_index]);
}

void uncache_host(struct host *host, int cache_index)
{
    assert(host);
    struct host_cache *cache = &host_caches[cache_index];
    pthread_rwlock_wrlock(&cache->rwlock);
    for (int i = 0; i < MAX_HOSTS_PER_CACHE; i++) {
        if (host == cache->hosts[i]) {
            uncache_host_internal(cache, i);
        }
    }
    pthread_rwlock_unlock(&cache->rwlock);
}

void clear_host_cache(int cache_index)
{
    assert(cache_index < MAX_HOST_CACHES);
    struct host_cache *cache = &host_caches[cache_index];
    pthread_rwlock_wrlock(&cache->rwlock);
    for (int i = 0; i < MAX_HOSTS_PER_CACHE; i++) {
        uncache_host_internal(cache, i);
    }
    pthread_rwlock_unlock(&cache->rwlock);
}

const char *get_ip(struct host *host)
{
    assert(host);
    return (const char *)host->address_string;
}
uint16_t get_port(const struct host *host)
{
    assert(host);
    return ntohs(host->address.sin_port);
}

// Decrements reference count and deletes
// the host once there are no more references
// from it's owning thread or any multicast caches
void release_host(struct host **host)
{
    assert(host);
    if (!(*host)) {
        return;
    }
    int refs = atomic_fetch_sub(&(*host)->reference_count, 1);
    if (refs > 1) {
        return;
    }
    if ((*host)->ssl) {
        int ssl_shutdown = 0;
        do {
            ssl_shutdown = SSL_shutdown((*host)->ssl);
        } while (!ssl_shutdown);
        if (ssl_shutdown < 0) {
            // TODO: Handle SSL shutdown errors
        }
        SSL_free((*host)->ssl);
    }
    close((*host)->socket);
    free(*host);
    *host = NULL;
}

int attempt_tls_handshake(struct host *host, SSL_CTX *ssl_context)
{
    assert(host && ssl_context);
    host->ssl = SSL_new(ssl_context);
    SSL_set_fd(host->ssl, host->socket);
    int ssl_accept_result = 0;

    while (ssl_accept_result <= 0) {
        ssl_accept_result = SSL_accept(host->ssl);
        if (ssl_accept_result <= 0) {
            int ssl_error = SSL_get_error(host->ssl, ssl_accept_result);
            if (ssl_error == SSL_ERROR_WANT_READ ||
                ssl_error == SSL_ERROR_WANT_WRITE) {
                continue;
            }
            //ERR_print_errors_fp(stderr);
            return -1;
        }
    }
    return 0;
}

void close_connection(struct host *host)
{
    assert(host);
    host->is_connected = 0;
    close(host->socket);
}

static int bind_host_socket(struct host *host)
{
    assert(host);
    assert(host->socket > 0);
    const struct sockaddr *bound_address =
        (struct sockaddr *)&host->address;
    if (FAILURE(bind(host->socket,
                     bound_address,
                     sizeof(host->address)))) {
        perror("Failed to bind socket!\n");
        if(FAILURE(close((int)host->socket))) {
            // TODO: Handle close() errors
        }
        return ERROR;
    }
    return SUCCESS;
}

int set_host_non_blocking(struct host *host)
{
    assert(host);
    const socketfd_t target_socket = host->socket;
    int flags = fcntl(target_socket, F_GETFL, 0);
    if (-1 == flags) {
        return ERROR;
    }
    if (-1 == fcntl(target_socket, F_SETFL, flags | O_NONBLOCK)) {
        perror("Error setting socket to non-blocking mode");
        return ERROR;
    }
    return SUCCESS;
}

// Returns -1 on error or 0 on success
int host_accept(struct host *dst_host,
                const struct host *listening_host)
{
    assert(dst_host && listening_host);
    dst_host->address_len = sizeof(struct sockaddr);
    socketfd_t sock = accept(listening_host->socket,
                             (struct sockaddr *)&dst_host->address,
                             &dst_host->address_len);
    if (0 > sock) {
        return -1;
    }
    dst_host->is_connected = 1;
    dst_host->socket = sock;
    return 0;
}

bool is_host_connected(const struct host *host)
{
    assert(host);
    return host->is_connected;
}


// returns -1 on error and 0 on success
int create_host_tcp_socket_nb(struct host *host)
{
    assert(host);
    host->socket = create_socket(SOCK_DEFAULT_TCP);
    if (host->socket < 0) {
        return -1;
    }
    set_host_non_blocking(host);
    return 0;
}

// returns 0 on success, nonzero on failure
int host_start_listening_tcp(struct host *host)
{
    assert(host);
    int er = 0;
    if (0 >= host->socket) {
        er = create_host_tcp_socket_nb(host);
        if (er) return ERROR;
    }
    if (FAILURE(bind_host_socket(host))) {
        perror("Failed to bind listen socket.\n");
        return ERROR;
    }
    if (FAILURE(listen(host->socket, SOCK_BACKLOG))) {
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
    assert(host);
    return host->is_listening;
}
ssize_t unencrypted_host_tcp_recv(struct host *remotehost,
                                  char *out_buffer,
                                  size_t buffer_size)
{
    assert(remotehost && out_buffer && (buffer_size > 0));
    memset(out_buffer, 0, buffer_size);
    return recv(remotehost->socket, out_buffer, buffer_size, 0);
}
ssize_t encrypted_host_tcp_recv(struct host *remotehost,
                                       char *out_buffer,
                                       size_t buffer_size)
{
    assert(remotehost && out_buffer && (buffer_size > 0));
    memset(out_buffer, 0, buffer_size);
    return (ssize_t)SSL_read(remotehost->ssl,
                             out_buffer,
                             buffer_size);
}
ssize_t send_tcp_unencrypted_internal(const struct host *remotehost,
                                      const char *data,
                                      ssize_t data_size)
{
    assert(remotehost && data && (data_size > 0));
    return (ssize_t)send(remotehost->socket,
                         data,
                         data_size,
                         0);
}
ssize_t send_tcp_encrypted_internal(const struct host *remotehost,
                                    const char *data,
                                    ssize_t data_size)
{
    assert(remotehost && data && (data_size > 0));
    return SSL_write(remotehost->ssl,
                     data,
                     data_size);
}

// Returns the amount of hosts that
// returned SEND_TRYAGAIN
// so we can call attempt_multicast again.
int multicast_tcp_internal(const char *data,
                           const ssize_t datasize,
                           int cache_index,
                           ssize_t (*send_func)(const char *data,
                                                const ssize_t datasize,
                                                struct host *remotehost))
{
    assert(data);
    struct host_cache *cache = &host_caches[cache_index];
    ssize_t statuses[MAX_HOSTS_PER_CACHE] = {0};
    const int send_tryagain = -2;
    bool unreached_hosts_remain = 1;

    for (int i = 0; i < MAX_HOSTS_PER_CACHE; i++) {
        statuses[i] = send_tryagain;
    }
    pthread_rwlock_rdlock(&cache->rwlock);
    while(unreached_hosts_remain) {
        for (int i = 0; i < MAX_HOSTS_PER_CACHE; i++) {
            if (!cache->hosts[i]) {
                continue;
            }
            struct host *remotehost = cache->hosts[i];
            if ((statuses[i] < datasize && statuses[i] > 0)
                || statuses[i] == send_tryagain) {
                statuses[i] = send_func(data, datasize, remotehost);
                unreached_hosts_remain = (statuses[i] < datasize
                                          && statuses[i] > 0
                                          && !unreached_hosts_remain)
                                          || statuses[i] == send_tryagain;
            }
        }
    }
    pthread_rwlock_unlock(&cache->rwlock);
    return 0;
}

// returns -1 on error, 1 on ready socket, 0 on socket not ready
int host_socket_select(struct host *host)
{
    assert(host);
    fd_set writefds;
    FD_ZERO(&writefds);
    FD_SET(host->socket, &writefds);
    // TODO: implement timout. Or better yet, epoll.
    int select_status = select(host->socket + 1,
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

int add_host_socket_to_epoll(struct host *host,
                             struct socket_epoller *epoller)
{
    // Add listening socket to epoll
    struct epoll_event event;
    event.data.ptr = host;
    event.events = EPOLLIN | EPOLLET; // Wait for incoming connections, edge-triggered

    if (epoll_ctl(epoller->epoll_fd, EPOLL_CTL_ADD, host->socket, &event) == -1) {
        perror("epoll_ctl");
        return -1;
    }
    return 0;
}
