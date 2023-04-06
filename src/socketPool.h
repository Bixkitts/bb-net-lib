#ifndef SOCKETPOOL
#define SOCKETPOOL

#define SOCK_MAX 2048               // Maximum amount of sockets open at once
#define SOCK_LUT SOCK_MAX/8         // LUT bytes for the avail
#define INVALID_FD(fd) ((fd) < 0)   // Check for invalid File Descriptor


#endif