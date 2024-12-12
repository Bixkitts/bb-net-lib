# Networking For Simpletons
No weird complicated parameters to configure, no 
confusing function names, no bullcrap.

The working man's transport layer IP communications.

## How Do I Use This Library?
You can either:
- Add it as a git submodule
- Install it and include it
- Download a release build
- Build it yourself

All of these are easy and convenient options.

### Git Submodule
- Enter the directory of your own git project
- git submodule add https://github.com/Bixkitts/bb-net-lib.git path/to/submodule
- git submodule update --init --recursive

And then to update this library while it's a submodule:
- git submodule update --remote path/to/submodule
(After being updated, you need to commit and push the changes to your remote)

### Install and Include It
- git clone https://github.com/Bixkitts/bb-net-lib.git
- cd bb-net-lib
- mkdir build
- cd build
- cmake -DCMAKE_INSTALL_PREFIX=/usr/local ..
- cmake --build . --target install

Add this to your CMakeLists.txt
- target_link_libraries(${PROJECT_NAME} PRIVATE bbnetlib)

Now you can include <b><bbnetlib.h></b> in your own project and get to coding.


If you're feeling fancy:
- find_package(bbnetlib 0.1 CONFIG REQUIRED)

If you <b>don't have cmake</b>, well then link the library via your own methods.

### Download a Release Build
- Download a release through the browser or wget/curl
- But the library and include header into a place your own project can use it
- include <b>"bbnetlib.h"</b> and link libbbnetlib.

### Build it Yourself
Follow the steps to <b>Install and Include It</b>,
except you do
- cmake --build .

without --target install.
Then do with the resultant libbbnetlib.a and include header as you see fit.

## Now, How Do I Write With It?
Here's TCP:
```c
// We want to store the localhost.
// I've used a global, but you can
// use accessors or a database or anything.
struct host *localhost = NULL;

void your_tcp_packet_handler (char* received_packet_data, 
                              ssize_t size_of_packet, 
                              struct host *host_that_sent_the_packet)
{
    // Enable TLS encryption
    enable_encryption();
    struct host *remotehost = host_that_sent_the_packet;
    // Send some data back
    const char data[] = "Hello there!";
    ssize_t    data_size = 13;
    send_data_tcp(data, datasize, remotehost);
    // We can cache this host
    // in up to 16 caches for
    // later multicasts!
    int cache_index = 0;
    cache_host(remotehost, cache_index);
    // Send the same packet to a cache full of hosts
    multicast_tcp(data, datasize, cache_index);
    // TCP:
    // We've decided we're completely done with this host,
    // Stop communicating with them.
    close_connections(remotehost);
    // We just need to close connections on the localhost
    // and then we escape the top level listen_tcp()
    // function!
    if (WERE_BORED) {
        close_connections(localhost)
    }
}
int main() 
{
    localhost = create_host("YOUR.IP", 1234);
    listen_tcp (localhost, your_tcp_packet_handler);
    return 0;
}
```
Here's UDP, it's almost the same:
```c
// We want to store the localhost.
// I've used a global, but you can
// use accessors or a database or anything.
struct host *local_host = NULL;

struct host *cached_remote_host;

void your_upd_packet_handler (char* received_packet_data, 
                              ssize_t size_of_packet, 
                              struct host *host_that_sent_the_packet)
{
    struct host *remotehost = host_that_sent_the_packet;
    // Get the IP of the remotehost:
    char ip[IP_ADDR_LEN] = get_ip(remotehost);
    // Send some data back
    const char data[] = "Hello there!";
    ssize_t    data_size = 13;
    // UDP is connectionless, we just send a packet
    // back to a remote host.
    send_data_udp(data, 13, remotehost);
    // We just need to close connections on the localhost
    // and then we escape the top level listenUDP()
    // function!
    if (WERE_BORED) {
        close_connections(localhost)
    }
}
int main() 
{
    localhost = create_host("YOUR.IP", 1234);
    listen_udp (localhost, your_udp_packet_handler);
    return 0;
}
```

Maximum packet size is <b>1024 bytes</b>, so you know it's a full packet when that's the received size.

Receiving a <b>packet size of 0</b> in the packet_handler means the remote host negotiated a disconnect,

and <b>-1 packet size</b> means an error (typically a timeout).

<b>TCP connections time out after 5 seconds</b> (this is compiled into the binary, you can change it if necessary).

## How Do I Help?
Hit me up and help me write it.

Request features by opening an issue.

## Encryption?
Yes, just enable_encryption() for TLS and have a certificate and key for it next to the binary.

## Planned Features
- Nothing really right now, I'm just using this to power my own webservers
  so I'll adjust it to fit those needs

## Known Issues, Beware!
I haven't touched UDP code in months,
it probably doesn't work but I'm actively using TCP
and TLS in another project so that should work fine
as described here.
