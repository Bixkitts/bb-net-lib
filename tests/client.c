#include <stdio.h>
#include "bbnetlib.h"
#include <unistd.h>
#include <time.h>

void sleep_ms(unsigned int milliseconds) {
    struct timespec req;
    req.tv_sec = milliseconds / 1000;
    req.tv_nsec = (milliseconds % 1000) * 1000000;
    nanosleep(&req, NULL);
}

int main(void)
{
    printf("\nWelcome to the test client!");
    printf("\n-------------------------------\n");
    struct host* remotehost = createHost("127.0.0.1", 80);
    connectToTCP (remotehost);
    sendDataTCP  ("Opening Connection!", 20, remotehost);
    for (int i = 0; i < 5; i++) {
        sendDataTCP  ("AAAAA", 6, remotehost);
        sleep_ms(10);
        sendDataTCP  ("BBBBB", 6, remotehost);
        sleep_ms(10);
    }
    sendDataTCP  ("Huh?", 5, remotehost);
    sleep_ms(50);
    sendDataTCP  ("end", 4, remotehost);
    return 0;

}

