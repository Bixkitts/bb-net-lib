# This is a library for sending and receiving TCP and UDP packets
It is built on the Linux socket headers

## Install Instructions:
- Create folders ./build and ./install
- cd to ./build
- run "cmake .." and wait for completion
- run "cmake --build . --target install" and wait for completion

The library will be installed in the "install" folder in the base directory.
Utilise it by adding the following lines to your project's CMakeLists.txt:

- find_package(bbnetlib 0.1 CONFIG REQUIRED)
- target_link_libraries(${PROJECT_NAME} PRIVATE netlib::bbnetlib)
