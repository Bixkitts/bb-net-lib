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
    if (IS_INVALID_FD(socket)) {
        perror("\nSocket creation failed");
        return ERROR;
    }
    return sockfd;
}

void close_socket(socketfd_t sockfd)
{
    close(sockfd);
}

int bind_socket(socketfd_t sockfd, struct host *localhost)
{
    struct sockaddr *bound_address = (struct sockaddr *)&localhost->address;
    if (FAILURE(bind(sockfd, bound_address, sizeof(localhost->address)))) {
        perror("\nFailed to bind socket!");
        return ERROR;
    }
    return SUCCESS;
}
int set_socket_non_block(socketfd_t sockfd)
{
    int flags = fcntl(sockfd, F_GETFL, 0);
    if (flags == -1) {
        return ERROR;
    }
    if (fcntl(sockfd, F_SETFL, flags | O_NONBLOCK) == -1) {
        perror("Error setting socket to non-blocking mode");
        return ERROR;
    }
    return SUCCESS;
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
