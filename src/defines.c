#include <stdio.h>
#include "defines.h"

const char *const err_strings[STR_ERROR_COUNT] = {
    "Unknown Error",
    "Malloc Error",
    "host cache index out of bounds"};

void debug_print(const char *format, ...)
{
#ifdef DEBUG
    va_list args;
    va_start(args, format);
    vfprintf(stderr, format, args);
    va_end(args);
#endif   
}
