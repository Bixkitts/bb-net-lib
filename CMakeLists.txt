cmake_minimum_required(VERSION 3.28)
set    (namespace "netlib")
project("bbnetlib"
	DESCRIPTION "Minimal IP Data transfer library"
	VERSION 0.1
)

# So language servers work
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

add_library   (${PROJECT_NAME} STATIC)
target_sources(${PROJECT_NAME} 
    PRIVATE 
        src/send.c
        src/listen.c
        src/defines.c
        src/clientObject.c
        src/socketsNetLib.c
        src/threadPool.c
        src/encryption.c
        src/configurer.c
)

target_include_directories(${PROJECT_NAME}
	PRIVATE
		${CMAKE_CURRENT_SOURCE_DIR}/src
	PUBLIC
	    # where top-level project will look for the library's public headers
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        # where external projects will look for the library's public headers
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

target_compile_options(${PROJECT_NAME} PRIVATE -fvisibility=hidden $<$<CONFIG:Debug>:-O0;-g3;-ggdb;-Wall;-Wextra;-Wpedantic;-Wno-unused-parameter;-fanalyzer;> $<$<CONFIG:Release>:-O3;-flto>)
target_compile_definitions(${PROJECT_NAME} PRIVATE $<$<CONFIG:Debug>: DEBUG>)

find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})
target_link_libraries(${PROJECT_NAME} PUBLIC ${OPENSSL_LIBRARIES})
###############################################################
# ------------- Test Binaries --------------------------------#
###############################################################
set (TEST_SERVER_NAME "testServer")
set (TEST_CLIENT_NAME "testClient")

# Server
add_executable  (${TEST_SERVER_NAME})
target_sources  (${TEST_SERVER_NAME} PRIVATE tests/server.c)
target_include_directories(${TEST_SERVER_NAME} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_compile_options(${TEST_SERVER_NAME} PRIVATE $<$<CONFIG:Debug>:-O0;-g3;-ggdb;-Wall> $<$<CONFIG:Release>:-O3;>)
target_compile_definitions(${TEST_SERVER_NAME} PRIVATE $<$<CONFIG:Debug>: DEBUG>)
target_link_libraries(${TEST_SERVER_NAME} PRIVATE ${PROJECT_NAME})

# Client
add_executable  (${TEST_CLIENT_NAME})
target_sources  (${TEST_CLIENT_NAME} PRIVATE tests/client.c)
target_include_directories(${TEST_CLIENT_NAME} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_compile_options(${TEST_CLIENT_NAME} PRIVATE $<$<CONFIG:Debug>:-O0;-g3;-ggdb;-Wall> $<$<CONFIG:Release>:-O3;>)
target_compile_definitions(${TEST_CLIENT_NAME} PRIVATE $<$<CONFIG:Debug>: DEBUG>)
target_link_libraries(${TEST_CLIENT_NAME} PRIVATE ${PROJECT_NAME})

###############################################################
# ----- Complicated installation-related stuff past here -----#
###############################################################
if(DEFINED CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
    message(
        STATUS
        "CMAKE_INSTALL_PREFIX is not set\n"
        "Default value: ${CMAKE_INSTALL_PREFIX}\n"
        "Will set it to ${CMAKE_SOURCE_DIR}/install"
    )
    set(CMAKE_INSTALL_PREFIX
        "${CMAKE_SOURCE_DIR}/install"
        CACHE PATH "Where the library will be installed to" FORCE
    )
else()
    message(
        STATUS
        "CMAKE_INSTALL_PREFIX was already set\n"
        "Current value: ${CMAKE_INSTALL_PREFIX}"
    )
endif()


# without it public headers won't get installed
set(public_headers
    include/bbnetlib.h
)

# note that ${public_headers} has to be in quotes
set_target_properties(${PROJECT_NAME} PROPERTIES PUBLIC_HEADER "${public_headers}")
set_target_properties(${PROJECT_NAME} PROPERTIES DEBUG_POSTFIX "d")

# if you haven't included it already
# definitions of CMAKE_INSTALL_LIBDIR, CMAKE_INSTALL_INCLUDEDIR and others
include(GNUInstallDirs)

# install the target and create export-set
install(TARGETS ${PROJECT_NAME}
    EXPORT "${PROJECT_NAME}Targets"
    # these get default values from GNUInstallDirs, no need to set them
    #RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR} # bin
    #LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR} # lib
    #ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR} # lib
    # except for public headers, as we want them to be inside a library folder
    PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/${PROJECT_NAME} # include/SomeLibrary
    INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR} # include
)
# generate and install export file
install(EXPORT "${PROJECT_NAME}Targets"
    FILE "${PROJECT_NAME}Targets.cmake"
    NAMESPACE ${namespace}::
    DESTINATION cmake
)
include(CMakePackageConfigHelpers)
# generate the version file for the config file
write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}ConfigVersion.cmake"
    VERSION "${version}"
    COMPATIBILITY AnyNewerVersion
)
# create config file
configure_package_config_file(${CMAKE_CURRENT_SOURCE_DIR}/Config.cmake.in
    "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}Config.cmake"
    INSTALL_DESTINATION cmake
)
# install config files
install(FILES
    "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}Config.cmake"
    "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}ConfigVersion.cmake"
    DESTINATION cmake
)
# generate the export targets for the build tree
export(EXPORT "${PROJECT_NAME}Targets"
    FILE "${CMAKE_CURRENT_BINARY_DIR}/cmake/${PROJECT_NAME}Targets.cmake"
    NAMESPACE ${namespace}::
)


