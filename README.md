# Networking For Simpletons
No weird complicated parameters to configure, no 
confusing function names, no bullcrap.

The working man's Transport layer IP communications.

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

Now you can include <bbnetlib.h> in your own project and get to coding
If you're feeling fancy:
- find_package(bbnetlib 0.1 CONFIG REQUIRED)

If you <b>don't have cmake</b>, well then link the library via your own methods.

### Download a Release Build
- Download a release through the browser or wget/curl
- But the library and include header into a place your own project can use it
- include "bbnetlib.h" and link libbbnetlib.

### Build it Yourself
Follow the steps to <b>Install and Include It</b>,
except you do
- cmake --build .
without --target install.
Then do with the resultant libbbnetlib.a and include header as you see fit.

## How Do I Help?
Hit me up and help me write it.
Request features by opening an issue.

## Planned Features
- OpenSSL Transport Layer Security (TLS)
- Websockets functions
- IPv6 support
- HTTP helper functions
- Maybe JSON parsing

## Known Issues, Beware!
Transmissions are currently not encrypted.
