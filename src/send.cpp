#include <iostream>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <strings.h>
#include <unistd.h>
#include "ClientObject.h"

int sendData(char *data, uint16_t datasize, Client &client)
  {
      socklen_t len = sizeof(client.Socket);    
  
      sendto(client.sockfd, data, datasize, MSG_CONFIRM, (const struct sockaddr *) &client.Socket, len);
      printf("Hello message sent.\n");
  
      return 0;
  }

