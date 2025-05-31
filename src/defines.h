#ifndef DEFINES
#define DEFINES

#include <stdarg.h>
// This is a static library so the visibility attribute
// won't do anything but you may also want to compile this
// as a shared library in which case this becomes valid.
#define BBNETAPI           __attribute((visibility("default")))

#define ERROR              (-1)
#define SUCCESS            0
#define FAILURE(func)      ((func) < 0)
#define NB_SOCK_TRY_AGAIN  -2

#define BITS_PER_BYTE      8

// The maximum size of individual packets
// coming in from UDP or TCP.
#define PACKET_BUFFER_SIZE 1024

enum err_string_enum {
    STR_ERROR_UNKNOWN,
    STR_ERROR_MALLOC,
    STR_ERROR_HOST_CACHE_INDEX,
    STR_ERROR_COUNT
};

extern const char *const err_strings[];
extern void debug_print(const char *format, ...);

#endif
