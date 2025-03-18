#include <arpa/inet.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <strings.h>
#include <sys/socket.h>
#include <unistd.h>

#include "clientObject.h"
#include "defines.h"
#include "socketsNetLib.h"

socketfd_t create_socket(socketfd_t value)
{
    socketfd_t sockfd = value;
    if (IS_INVALID_FD(sockfd)) {
        perror("Socket creation failed");
        return ERROR;
    }
    return sockfd;
}

void close_socket(socketfd_t sockfd)
{
    close(sockfd);
}

/*
 * This only works for blocking sockets,
 * don't use.
 */
int set_socket_timeout(socketfd_t sockfd, long secs)
{
    struct timeval timeout = {};
    timeout.tv_sec         = secs; // 5 seconds
    timeout.tv_usec        = 0;    // 0 microseconds
    if (FAILURE(setsockopt(sockfd,
                           SOL_SOCKET,
                           SO_RCVTIMEO,
                           (char *)&timeout,
                           sizeof(timeout)))) {
        perror("\nSetsockopt error");
    }
    if (FAILURE(setsockopt(sockfd,
                           SOL_SOCKET,
                           SO_SNDTIMEO,
                           (char *)&timeout,
                           sizeof(timeout)))) {
        perror("\nSetsockopt error");
    }

    return 0;
}

int init_socket_poller(struct socket_epoller *epoller)
{
    memset(epoller, 0, sizeof(*epoller));
    int epoll_fd = epoll_create1(0); // Create epoll instance
    if (epoll_fd == -1) {
        perror("epoll_create1");
    }
    epoller->epoll_fd = epoll_fd;
    return epoll_fd;
}

void destroy_socket_poller(struct socket_epoller *epoller)
{
    close(epoller->epoll_fd);
}

int add_socket_to_epoll(struct host *host, struct socket_epoller *epoller)
{
    // Add listening socket to epoll
    struct epoll_event event;
    event.data.ptr = host;
    event.events = EPOLLIN | EPOLLET; // Wait for incoming connections, edge-triggered

    if (epoll_ctl(epoller->epoll_fd, EPOLL_CTL_ADD, get_socket(host), &event) == -1) {
        perror("epoll_ctl");
        return -1;
    }
    return 0;
}
