#include <stdio.h>
#include "bbnetlib.h"
Host localhost = NULL;

void testPacketHandler(char *data, ssize_t packetSize, Host remotehost)
{
    if (packetSize > 0) {
        printf("\nReceived the following string: %s", data);
    }
    if (packetSize == 0) {
        printf("\nRemotehost negotiated shutdown...");
        closeConnections(remotehost);
    }
    if (packetSize < 0) {
        printf("\nThere was some sort of problem.");
        closeConnections(remotehost);
    }
    return;
}

int main(void)
{
    printf("\nWelcome to the test server!");
    printf("\n-----------------------------------\n");
    localhost = createHost("0.0.0.0", 80);
    listenForTCP(localhost, testPacketHandler);
    return 0;
}
