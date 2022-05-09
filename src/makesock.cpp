#include <iostream>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <strings.h>
#include <unistd.h>

int makesock()
{
      sockaddr_in server, sender;//Two socket addresses
  
      int sockfd;//this is the datagram socket and returns a file descriptor.
      if ( (sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0 ) { 
          perror("socket creation failed"); //perror is a system call to write an error.
          exit(EXIT_FAILURE);
      }   
      //"bzero" is a syscall to zero all the bytes
      bzero((char *) &server, sizeof(server));
      bzero((char *) &sender, sizeof(sender));
  
      //filling in the data of the server's ip.
      server.sin_family = AF_INET;
      server.sin_port = htons(54000);
      inet_pton(AF_INET, "0.0.0.0", &server.sin_addr);
      //bind the socket "sockfd" to the address and port in the sockaddr struct "server"
      bind(sockfd, (struct sockaddr *) &server, sizeof(server));
  
      int n;
	  socklen_t len;
  
      len = sizeof(sender);  //len is value/resuslt

	return 0;
}
