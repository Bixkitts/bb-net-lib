#ifndef SOCKETPOOL
#define SOCKETPOOL

#define SOCK_MAX 2048               // Maximum amount of sockets open at once
#define SOCK_LUT SOCK_MAX/8         // LUT bytes for the avail
#define INVALID_FD(fd) ((fd) < 0)   // Check for invalid File Descriptor

typedef int socketfd;               // File descriptor for a socket
typedef int socketIndex;                                    

extern socketIndex createSocket();         // Create a new socket in the global pool
                                        // and return it
static int findFreeSocket(int* index);  // Writes the first free index for a socket
                                        // into "index"

#endif
