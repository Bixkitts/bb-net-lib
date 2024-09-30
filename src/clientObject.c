#include <netinet/in.h>
#include <pthread.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <strings.h>
#include <unistd.h>
#include <string.h>
#include <stdatomic.h>

#include "socketsNetLib.h"
#include "clientObject.h"
#include "encryption.h"

static pthread_mutex_t cacheLock[MAX_HOST_CACHES] = {PTHREAD_MUTEX_INITIALIZER};

static struct host* hostCache     [MAX_HOST_CACHES][MAX_HOSTS_PER_CACHE] = {0};

static atomic_int hostIDCounter = ATOMIC_VAR_INIT(0);

static int  getFreeCacheSpot       (int cacheIndex);
static void removeHostAtCacheIndex (int cacheIndex, int hostIndex);

struct host* createHost(const char *ip, const uint16_t port)
{
    struct host* host = NULL;

    host = (struct host*)calloc(1, sizeof(struct host));
    if (host == NULL) {
        perror(errStrings[STR_ERROR_MALLOC]);
        return NULL;
    }
    //filling in the data of the host's ip.
    strcpy(host->addressStr, ip);
    host->id                 = atomic_fetch_add(&hostIDCounter, 1);
    host->address.sin_family = AF_INET;
    host->address.sin_port   = htons(port);

    inet_pton            (AF_INET, ip, &host->address.sin_addr);
    return host;
}

void copyHost(struct host* dstHost, struct host* srcHost)
{
    memcpy (dstHost, 
            srcHost, 
            sizeof(struct host));
}

void *getHostCustomAttr(struct host* host)
{
    return host->customAttribute;
}

void setHostCustomAttr(struct host* host, void* ptr)
{
    host->customAttribute = ptr;
}
bool isCached(struct host* host)
{
    return host->isCached;
}
static int getFreeCacheSpot(int cacheIndex)
{
    for (int i = 0; i < MAX_HOSTS_PER_CACHE; i++) {
        if (hostCache[cacheIndex][i] == NULL) {
            return i;
        }
    }
    return -1;
}
static void removeHostAtCacheIndex(int cacheIndex, int hostIndex)
{
    struct host *host = hostCache[cacheIndex][hostIndex];
    if (host != NULL) {
        host->isCached = 0;
        hostCache[cacheIndex][hostIndex] = NULL;
    }
}
void cacheHost(struct host* host, int cacheIndex)
{
    pthread_mutex_lock   (&cacheLock[cacheIndex]);

    if (cacheIndex >= MAX_HOST_CACHES) {
        fprintf(stderr, "\n%s", errStrings[STR_ERROR_HOST_CACHE_INDEX]);
        goto unlock;
    }
    int spot = getFreeCacheSpot(cacheIndex);
    if (spot != -1) {
        hostCache[cacheIndex][spot] = host;
        host->isCached = 1;
    }
    else {
        fprintf(stderr, "\nHost cache full, can't add host %s", getIP(host));
    }
unlock:
    pthread_mutex_unlock (&cacheLock[cacheIndex]);
}
void uncacheHost(struct host* host, int cacheIndex)
{
    pthread_mutex_lock   (&cacheLock[cacheIndex]);
    for (int i = 0; i < MAX_HOSTS_PER_CACHE; i++) {
        if (host == getHostFromCache(cacheIndex, i)) {
            removeHostAtCacheIndex(cacheIndex, i);
            break;
        }
    }
    pthread_mutex_unlock (&cacheLock[cacheIndex]);
}
void clearHostCache(int cacheIndex)
{
    pthread_mutex_lock   (&cacheLock[cacheIndex]);
    if (cacheIndex >= MAX_HOST_CACHES) {
        fprintf(stderr, "\n%s", errStrings[STR_ERROR_HOST_CACHE_INDEX]);
        goto unlock;
    }
    for (int i = 0; i < MAX_HOSTS_PER_CACHE; i++) {
        removeHostAtCacheIndex(cacheIndex, i);
    }
unlock:
    pthread_mutex_unlock (&cacheLock[cacheIndex]);
}
struct host *getHostFromCache(int cacheIndex, int hostIndex)
{
    return hostCache[cacheIndex][hostIndex];
}
const char* getIP(struct host* host)
{
    return (const char*)host->addressStr;
}
uint16_t getPort(struct host* host)
{
    return ntohs(host->address.sin_port);
}
int getHostID(struct host *host)
{
    return host->id;
}
void destroyHost(struct host** host)
{
    if (*host == NULL) {
        return;
    }
    if ((*host)->isCached == 1) {
        return;
    }
    if ((*host)->ssl != NULL) {
        int shutdownResult;
        do {
            shutdownResult = SSL_shutdown((*host)->ssl);
        } while (shutdownResult == 0);
        if (shutdownResult < 0) {
            // Handle error if necessary
        }
        SSL_free((*host)->ssl);
    }

    closeSocket  (getSocket(*host));

    free(*host);
    *host = NULL;
}

int attemptTLSHandshake(struct host* host, SSL_CTX *sslContext)
{
    host->ssl = SSL_new(sslContext);
    SSL_set_fd(host->ssl, getSocket(host));
    int ssl_accept_result = 0;

    while (ssl_accept_result <=0) {
        ssl_accept_result = SSL_accept(host->ssl);
        if (ssl_accept_result <= 0) {
            int ssl_error = SSL_get_error(host->ssl, ssl_accept_result);
            if (ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE) {
                continue;
            }
            ERR_print_errors_fp(stderr);
            return -1;
        }
    }
    return 0;
}

void closeConnections(struct host* host)
{
    host->bListen = 0;
}

void setCommunicating(struct host* host)
{
    host->bListen = 1;
}

bool isCommunicating(const struct host* host)
{
    return host->bListen;
}

void setSocket(struct host *restrict host, socketfd_t sockfd)
{
    host->associatedSocket = sockfd;
}

socketfd_t getSocket(const struct host* host)
{
    return host->associatedSocket;
}

SSL *getHostSSL(const struct host *restrict host)
{
    return host->ssl;
}
