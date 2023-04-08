#ifndef SOCKETPOOL
#define SOCKETPOOL

#define IS_INVALID_FD(fd) ((fd) < 0)    // Check for invalid File Descriptor
#define INVALID_FD -1                   // Potential return for socket creation
#define SOCK_DEFAULT 0                  // Creating a socket without passing in a value
#define SOCK_BACKLOG 5                  // Potential socket backlog when listening

#include "clientObject.h"
#include "socketfd.h"

                                    
extern socketfd createSocket(socketfd value);       // Create a new socket 
                                                    // Pass SOCK_DEFAULT for a plain IP socket
extern void closeSocket(socketfd socket);
extern int bindSocket(socketfd sockfd, Client* localhost);

#endif
