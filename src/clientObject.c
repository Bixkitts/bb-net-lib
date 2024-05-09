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

static pthread_mutex_t copyLock  = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t cacheLock[MAX_HOST_CACHES] = {PTHREAD_MUTEX_INITIALIZER};

static Host* hostCache     [MAX_HOST_CACHES][MAX_HOSTS_PER_CACHE] = {0};
static int   cacheOccupancy[MAX_HOST_CACHES]                      = {0};

static atomic_int hostIDCounter = ATOMIC_VAR_INIT(0);

Host* createHost(const char *ip, const uint16_t port)
{
    Host* host = NULL;

    host = (struct Host*)calloc(1, sizeof(struct Host));
    if (host == NULL) {
        perror(errStrings[STR_ERROR_MALLOC]);
        return NULL;
    }
    //filling in the data of the host's ip.
    strcpy((char*)host->addressStr, ip);
    host->id                 = atomic_fetch_add(&hostIDCounter, 1);
    host->address.sin_family = AF_INET;
    host->address.sin_port   = htons(port);

    inet_pton            (AF_INET, ip, &host->address.sin_addr);
    return host;
}

void fastCopyHost(Host* dstHost, Host* srcHost)
{
    memcpy(dstHost, srcHost, sizeof(Host));
}
void copyHost(Host* dstHost, Host* srcHost)
{
    // Multiple threads could be caching hosts
    // to the same memory, this should prevent race conditions.
    pthread_mutex_lock   (&copyLock);
    memcpy               (dstHost, 
                          srcHost, 
                          sizeof(Host));
    pthread_mutex_unlock (&copyLock);
}

void *getHostCustomAttr(Host* host)
{
    return host->customAttribute;
}

void setHostCustomAttr(Host* host, void* ptr)
{
    host->customAttribute = ptr;
}
bool isCached(Host* host)
{
    return host->isCached;
}
void cacheHost(Host* host, int cacheIndex)
{
    pthread_mutex_lock   (&cacheLock[cacheIndex]);
    if (cacheIndex >= MAX_HOST_CACHES) {
        fprintf(stderr, "\n%s", errStrings[STR_ERROR_HOST_CACHE_INDEX]);
        goto unlock;
    }
    if (cacheOccupancy[cacheIndex] < MAX_HOSTS_PER_CACHE) {
        hostCache[cacheIndex][cacheOccupancy[cacheIndex]] = host;
        cacheOccupancy[cacheIndex]++;
        host->isCached = 1;
    }
    else {
        fprintf(stderr, "\nHost cache full, can't add host %s", getIP(host));
    }
unlock:
    pthread_mutex_unlock (&cacheLock[cacheIndex]);
}
void clearHostCache(int cacheIndex)
{
    pthread_mutex_lock   (&cacheLock[cacheIndex]);
    if (cacheIndex >= MAX_HOST_CACHES) {
        fprintf(stderr, "\n%s", errStrings[STR_ERROR_HOST_CACHE_INDEX]);
        goto unlock;
    }
    for (int i = 0; i < cacheOccupancy[cacheIndex]; i++) {
       Host* hostToDelete = getHostFromCache(cacheIndex, i);
       hostToDelete->isCached = 0;
       destroyHost(&hostToDelete);
    }
    cacheOccupancy[cacheIndex] = 0;
unlock:
    pthread_mutex_unlock (&cacheLock[cacheIndex]);
}
Host *getHostFromCache(int cacheIndex, int hostIndex)
{
    return hostCache[cacheIndex][hostIndex];
}
const int getCacheOccupancy(int cacheIndex)
{
    return cacheOccupancy[cacheIndex];
}
const char* getIP(Host* host)
{
    return (const char*)host->addressStr;
}
uint16_t getPort(Host* host)
{
    return ntohs(host->address.sin_port);
}
int getHostID(Host *host)
{
    return host->id;
}
void destroyHost(Host** host)
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

int attemptTLSHandshake(Host* host, SSL_CTX *sslContext)
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

void closeConnections(Host* host)
{
    host->bListen = 0;
}

void setCommunicating(Host* host)
{
    host->bListen = 1;
}

bool isCommunicating(const Host* host)
{
    return host->bListen;
}

void setSocket(Host *restrict host, socketfd sockfd)
{
    host->associatedSocket = sockfd;
}

socketfd getSocket(const Host* host)
{
    return host->associatedSocket;
}

SSL *getHostSSL(const Host *restrict host)
{
    return host->ssl;
}
