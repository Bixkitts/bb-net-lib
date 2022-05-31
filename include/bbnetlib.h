#ifndef BBNETLIB
#define BBNETLIB
#include <iostream>
namespace netlib
{
    int sendData(char *data, uint16_t datasize);
    int listenForData(char *buffer, uint16_t bufsize);
    int createClient(char *ip, u_short port);
}
#endif
