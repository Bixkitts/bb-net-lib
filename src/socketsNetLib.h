#ifndef SOCKETPOOL
#define SOCKETPOOL

// Check for invalid File Descriptor
#define IS_INVALID_FD(fd) ((fd) < 0)                       
#define INVALID_FD       -1                                      
// Default socket Types, IPv4 TCP/UDP
#define SOCK_DEFAULT_TCP socket(AF_INET, SOCK_STREAM, 0)   
#define SOCK_DEFAULT_UDP socket(AF_INET, SOCK_DGRAM, 0)    
// How many connections can queue up for being accepted
#define SOCK_BACKLOG     5                                      

#include "clientObject.h"
#include "socketfd.h"

extern socketfd createSocket      (socketfd value);
extern void     closeSocket       (socketfd socket);
extern int      bindSocket        (socketfd sockfd, 
                                   Host* localhost);
extern int      setSocketNonBlock (socketfd sockfd);
extern int      setSocketTimeout  (socketfd sockfd, 
                                   long secs);

#endif
