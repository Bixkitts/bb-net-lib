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

extern socketfd_t createSocket      (socketfd_t value);
extern void     closeSocket       (socketfd_t socket);
extern int      bindSocket        (socketfd_t sockfd, 
                                   struct host* localhost);
extern int      setSocketNonBlock (socketfd_t sockfd);
extern int      setSocketTimeout  (socketfd_t sockfd, 
                                   long secs);

#endif
