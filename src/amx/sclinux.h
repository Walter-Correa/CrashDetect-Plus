/*
 * Things needed to compile under Linux / POSIX.
 */
#ifndef SCLINUX_H
#define SCLINUX_H

#if !defined stricmp
  #define stricmp(a,b)    strcasecmp(a,b)
#endif
#if !defined strnicmp
  #define strnicmp(a,b,c) strncasecmp(a,b,c)
#endif

#define DIRECTORY_SEP_CHAR      '/'
#define DIRECTORY_SEP_STR       "/"

#if !defined __BYTE_ORDER
  #if defined __linux__ || defined LINUX
    #include <endian.h>
  #else
    #include <stdlib.h>
  #endif
#endif

#if defined __OpenBSD__ || defined __FreeBSD__ || defined __APPLE__
  #if !defined __BYTE_ORDER && defined BYTE_ORDER
    #define __BYTE_ORDER    BYTE_ORDER
    #define __LITTLE_ENDIAN LITTLE_ENDIAN
    #define __BIG_ENDIAN    BIG_ENDIAN
  #elif !defined __BYTE_ORDER && defined __BYTE_ORDER__
    #define __BYTE_ORDER    __BYTE_ORDER__
    #define __LITTLE_ENDIAN __ORDER_LITTLE_ENDIAN__
    #define __BIG_ENDIAN    __ORDER_BIG_ENDIAN__
  #endif
#endif

#if !defined __BYTE_ORDER && defined __BYTE_ORDER__
  #define __BYTE_ORDER    __BYTE_ORDER__
  #define __LITTLE_ENDIAN __ORDER_LITTLE_ENDIAN__
  #define __BIG_ENDIAN    __ORDER_BIG_ENDIAN__
#endif

#endif /* SCLINUX_H */
