# This is a library for sending data across UDP

##Install Instructions:

-Create a folders ./build and ./install
-cd to ./build
-run "cmake .." and wait for completion
-run "cmake --build . --target install" and wait for completion

The library will be installed in the "install" folder in the base directory.
Utilise it by adding the following lines to your project's CMakeLists.txt:

set(CMAKE_PREFIX_PATH "wherever you keep your source/bb-net-library/install")
find_package(bbnetlib 0.1 CONFIG REQUIRED)

target_link_libraries(${PROJECT_NAME} PRIVATE netlib::bbnetlib)
