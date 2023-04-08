#ifndef DEFINES
#define DEFINES
// This is a static library so the visibility attribute
// won't do anything but you may also want to compile this
// as a shared library in which case this becomes valid.
#define BBNETAPI __attribute((visibility("default")))
#define ERROR -1
#define SUCCESS 0
#define FAILURE(func) ((func) == ERROR)
#define BITS_PER_BYTE 8

#endif
