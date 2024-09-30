#include <arpa/inet.h>
#include <netinet/in.h>
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
#include "encryption.h"
#include "socketsNetLib.h"

static pthread_mutex_t cache_lock[MAX_HOST_CACHES] = {
    PTHREAD_MUTEX_INITIALIZER};

static struct host *host_cache[MAX_HOST_CACHES][MAX_HOSTS_PER_CACHE] = {0};

static atomic_int host_id_counter = ATOMIC_VAR_INIT(0);

static int get_free_cache_spot(int cacheIndex);
static void remove_host_at_cache_index(int cacheIndex, int hostIndex);

struct host *create_host(const char *ip, const uint16_t port)
{
    struct host *host = NULL;

    host = (struct host *)calloc(1, sizeof(struct host));
    if (host == NULL) {
        perror(err_strings[STR_ERROR_MALLOC]);
        return NULL;
    }
    // filling in the data of the host's ip.
    strcpy(host->addressStr, ip);
    host->id                 = atomic_fetch_add(&host_id_counter, 1);
    host->address.sin_family = AF_INET;
    host->address.sin_port   = htons(port);

    inet_pton(AF_INET, ip, &host->address.sin_addr);
    return host;
}

void copy_host(struct host *dstHost, struct host *srcHost)
{
    memcpy(dstHost, srcHost, sizeof(struct host));
}

void *get_host_custom_attr(struct host *host)
{
    return host->customAttribute;
}

void set_host_custom_attr(struct host *host, void *ptr)
{
    host->customAttribute = ptr;
}
bool is_cached(struct host *host)
{
    return host->isCached;
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
        host->isCached                    = 0;
        host_cache[cacheIndex][hostIndex] = NULL;
    }
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
        host->isCached               = 1;
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
    return (const char *)host->addressStr;
}
uint16_t get_port(struct host *host)
{
    return ntohs(host->address.sin_port);
}
int get_host_id(struct host *host)
{
    return host->id;
}
void destroy_host(struct host **host)
{
    if (*host == NULL) {
        return;
    }
    if ((*host)->isCached == 1) {
        return;
    }
    if ((*host)->ssl != NULL) {
        int shutdown_result;
        do {
            shutdown_result = SSL_shutdown((*host)->ssl);
        } while (shutdown_result == 0);
        if (shutdown_result < 0) {
            // Handle error if necessary
        }
        SSL_free((*host)->ssl);
    }

    close_socket(get_socket(*host));

    free(*host);
    *host = NULL;
}

int attempt_tls_handshake(struct host *host, SSL_CTX *sslContext)
{
    host->ssl = SSL_new(sslContext);
    SSL_set_fd(host->ssl, get_socket(host));
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
    host->bListen = 0;
}

void set_communicating(struct host *host)
{
    host->bListen = 1;
}

bool is_communicating(const struct host *host)
{
    return host->bListen;
}

void set_socket(struct host *restrict host, socketfd_t sockfd)
{
    host->associatedSocket = sockfd;
}

socketfd_t get_socket(const struct host *host)
{
    return host->associatedSocket;
}

SSL *get_host_ssl(const struct host *restrict host)
{
    return host->ssl;
}
