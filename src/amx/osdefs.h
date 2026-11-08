/* __MSDOS__    set when compiling for DOS (not Windows)
 * _Windows     set when compiling for any version of Microsoft Windows
 * __WIN32__    set when compiling for Windows95 or WindowsNT (32 bit mode)
 * __32BIT__    set when compiling in 32-bit "flat" mode (DOS or Windows)
 * __64BIT__    set when compiling in 64-bit mode
 *
 * Copyright 1998-2006, ITB CompuPhase, The Netherlands.
 * info@compuphase.com.
 */

#ifndef _OSDEFS_H
#define _OSDEFS_H

#if defined(__WATCOMC__)
#  if defined(__WINDOWS__) || defined(__NT__)
#    define _Windows    1
#  endif
#  ifdef __386__
#    define __32BIT__   1
#  endif
#  if defined(_Windows) && defined(__32BIT__)
#    define __WIN32__   1
#  endif
#elif defined(_MSC_VER)
#  if defined(_WINDOWS) || defined(_WIN32)
#    define _Windows    1
#  endif
#  ifdef _WIN32
#    define __WIN32__   1
#    if defined(_WIN64)
#      ifndef __64BIT__
#        define __64BIT__ 1
#      endif
#    else
#      define __32BIT__ 1
#    endif
#  endif
#elif defined(__GNUC__) || defined(__clang__)
#  if defined(_WIN32) || defined(__WIN32__)
#    define _Windows    1
#    define __WIN32__   1
#  endif
#  if defined(_LP64) || defined(__LP64__) || defined(_WIN64) || defined(__x86_64__) || defined(__aarch64__)
#    ifndef __64BIT__
#      define __64BIT__ 1
#    endif
#  else
#    ifndef __32BIT__
#      define __32BIT__ 1
#    endif
#  endif
#endif

#if (defined __linux || defined __linux__) && !defined LINUX
  #define LINUX 1
#endif

#if defined __FreeBSD__
  #include <sys/endian.h>
#elif defined LINUX
  #include <endian.h>
#endif

#if !defined BIG_ENDIAN
  #define BIG_ENDIAN    4321
#endif
#if !defined LITTLE_ENDIAN
  #define LITTLE_ENDIAN 1234
#endif

#if !defined BYTE_ORDER
  #if defined UCLINUX
    #define BYTE_ORDER BIG_ENDIAN
  #else
    #define BYTE_ORDER LITTLE_ENDIAN
  #endif
#endif

#if defined __MSDOS__ || defined __WIN32__ || defined _Windows
  #define DIRSEP_CHAR '\\'
#elif defined macintosh
  #define DIRSEP_CHAR ':'
#else
  #define DIRSEP_CHAR '/'
#endif

#if !defined _MAX_PATH
  #include <stdio.h>
  #include <stdlib.h>
  #if !defined _MAX_PATH
    #if defined MAX_PATH
      #define _MAX_PATH    MAX_PATH
    #else
      #include <limits.h>
      #if defined PATH_MAX
        #define _MAX_PATH  PATH_MAX
      #elif defined _POSIX_PATH_MAX
        #define _MAX_PATH  _POSIX_PATH_MAX
      #else
        #define _MAX_PATH  1024
      #endif
    #endif
  #endif
#endif

#endif /* _OSDEFS_H */
