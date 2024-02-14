#include <stdio.h>
#include "bbnetlib.h"

int main(void)
{
    printf("\nWelcome to the test client!");
    printf("\n-------------------------------");
    Host remotehost = createHost("127.0.0.1", 7777);
    connectToTCP(remotehost);
    sendDataTCP("Hello!", 7, remotehost);
    return 0;
}

