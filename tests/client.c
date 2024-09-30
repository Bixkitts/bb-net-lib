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
    struct host* remotehost = create_host("127.0.0.1", 80);
    connect_to_tcp (remotehost);
    send_data_tcp("Opening Connection!", 20, remotehost);
    for (int i = 0; i < 5; i++) {
        send_data_tcp  ("AAAAA", 6, remotehost);
        sleep_ms(10);
        send_data_tcp  ("BBBBB", 6, remotehost);
        sleep_ms(10);
    }
    send_data_tcp  ("Huh?", 5, remotehost);
    sleep_ms(50);
    send_data_tcp  ("end", 4, remotehost);
    return 0;

}

