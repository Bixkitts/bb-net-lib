#include <stdio.h>
#include "bbnetlib.h"
#include <unistd.h>

struct host* localhost = NULL;

void test_packet_handler(char *data, ssize_t packet_size, struct host* remotehost)
{
    printf("\nReceived data:");
    for (int i = 0; i < packet_size; i++) {
        printf("%c", data[i]);
    }
    printf("\n");
    return;
}

int main(void)
{
    printf("\nWelcome to the test server!");
    printf("\n-----------------------------------\n");
    localhost = create_host("0.0.0.0", 80);
    listen_for_tcp(localhost, test_packet_handler);
    return 0;
}
