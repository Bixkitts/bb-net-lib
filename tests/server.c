#include <stdio.h>
#include "bbnetlib.h"
Host localhost = NULL;

void testPacketHandler(char *data, ssize_t packetSize, Host remotehost)
{
    printf("\nReceived the following string: %s", data);
    return;
}

int main(void)
{
    printf("\nWelcome to the test server!");
    printf("\n-----------------------------------");
    localhost = createHost("0.0.0.0", 7777);
    listenForTCP(localhost, testPacketHandler);
    return 0;
}
