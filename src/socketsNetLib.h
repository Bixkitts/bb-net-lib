#ifndef SOCKETPOOL
#define SOCKETPOOL

// Check for invalid File Descriptor
#define IS_INVALID_FD(fd) ((fd) < 0)
#define INVALID_FD        -1
// Default socket Types, IPv4 TCP/UDP
#define SOCK_DEFAULT_TCP  socket(AF_INET, SOCK_STREAM, 0)
#define SOCK_DEFAULT_UDP  socket(AF_INET, SOCK_DGRAM, 0)
// How many connections can queue up for being accepted
#define SOCK_BACKLOG      5

#define MAX_EPOLL_EVENTS  32

#include <sys/epoll.h>

#include "clientObject.h"
#include "socketfd.h"

struct socket_epoller {
    int epoll_fd;
    struct epoll_event events[MAX_EPOLL_EVENTS];
};

extern socketfd_t create_socket(socketfd_t value);
extern void close_socket(socketfd_t socket);
extern int bind_socket(socketfd_t sockfd, struct host *localhost);
extern int set_socket_non_block(socketfd_t sockfd);
extern int set_socket_timeout(socketfd_t sockfd, long secs);

/* Initialise an epoller we can use later.
 * returns -1 on error */
extern int init_socket_poller(struct socket_epoller *epoller);

/* Adds the socket associated with a host
 * to the epoll list in a socket_poller
 * so when we epoll_wait(), it's included. */
extern int add_socket_to_epoll(struct host *host, struct socket_epoller *epoller);
extern void destroy_socket_poller(struct socket_epoller *epoller);

#endif
