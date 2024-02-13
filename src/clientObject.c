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

#include "clientObject.h"

static pthread_mutex_t copyLock  = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t cacheLock = PTHREAD_MUTEX_INITIALIZER;

static Host hostCache     [MAX_HOST_CACHES][MAX_HOSTS_PER_CACHE] = {0};
static int  cacheOccupancy[MAX_HOST_CACHES]                      = {0};

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
    host->id                 = atomic_load(&hostIDCounter);
    strcpy((char*)host->addressStr, ip);
    host->address.sin_family = AF_INET;
    host->address.sin_port   = htons(port);

    atomic_fetch_add     (&hostIDCounter, 1);
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
void cacheHost(Host* host, int cacheIndex)
{
    pthread_mutex_lock   (&cacheLock);
    if (cacheIndex >= MAX_HOST_CACHES) {
        fprintf(stderr, "\n%s", errStrings[STR_ERROR_HOST_CACHE_INDEX]);
        goto unlock;
    }
    if (cacheOccupancy[cacheIndex] < MAX_HOSTS_PER_CACHE) {
        fastCopyHost(&hostCache[cacheIndex][cacheOccupancy[cacheIndex]], host);
        cacheOccupancy[cacheIndex]++;
    }
unlock:
    pthread_mutex_unlock (&cacheLock);
}
void clearHostCache(int cacheIndex)
{
    pthread_mutex_lock   (&cacheLock);
    if (cacheIndex >= MAX_HOST_CACHES) {
        fprintf(stderr, "\n%s", errStrings[STR_ERROR_HOST_CACHE_INDEX]);
        goto unlock;
    }
    cacheOccupancy[cacheIndex] = 0;
unlock:
    pthread_mutex_unlock (&cacheLock);
}
Host *getHostFromCache(int cacheIndex, int hostIndex)
{
    return hostCache[cacheIndex];
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
    if (*host != NULL) {
        free(*host);
        *host = NULL;
    }
}

void closeConnections(Host* host)
{
    // Should be fine without mutex lock,
    // is volatile and will only ever
    // be UNSET asyncronously to break
    // out of a loop, and not set.
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

void setSocket(Host* host, socketfd sockfd)
{
    host->associatedSocket = sockfd;
}

socketfd getSocket(const Host* host)
{
    return host->associatedSocket;
}
