#ifndef SOCKETPOOL
#define SOCKETPOOL

#define SOCK_MAX 2048               // Maximum amount of sockets open at once
#define SOCK_LUT SOCK_MAX/8         // LUT bytes for the avail
#define IS_INVALID_FD(fd) ((fd) < 0)   // Check for invalid File Descriptor
#define INVALID_FD -1

typedef int socketfd;               // File descriptor for a socket
typedef int socketIndex;            // An Integer that is an index in socketPool[]                        

extern socketIndex createSocket();         // Create a new socket in the global pool
extern void closeSocket(socketIndex index);
extern socketfd getSocketAtIndex(socketIndex index);
                                        // and return it
static int findFreeSocket(int* index);  // Writes the first free index for a socket
                                        // into "index", returns -1 when no socket is found


#endif
