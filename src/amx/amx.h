/*  Pawn Abstract Machine (for the Pawn language)
 *
 *  Copyright (c) ITB CompuPhase, 1997-2006
 *  Modified for CrashDetect (Zeex, Y-Less) and CrashDetect Plus (open.mp 32/64-bit, Pawn 3.10+, Fast Native Tracking)
 *
 *  This software is provided "as-is", without any express or implied warranty.
 *  In no event will the authors be held liable for any damages arising from
 *  the use of this software.
 *
 *  Permission is granted to anyone to use this software for any purpose,
 *  including commercial applications, and to alter it and redistribute it
 *  freely, subject to the following restrictions:
 *
 *  1.  The origin of this software must not be misrepresented; you must not
 *      claim that you wrote the original software. If you use this software in
 *      a product, an acknowledgment in the product documentation would be
 *      appreciated but is not required.
 *  2.  Altered source versions must be plainly marked as such, and must not be
 *      misrepresented as being the original software.
 *  3.  This notice may not be removed or altered from any source distribution.
 */

#ifndef AMX_H_INCLUDED
#define AMX_H_INCLUDED

#include <stdlib.h>   /* for size_t */
#include <limits.h>
#include <stdint.h>

#if (defined __linux || defined __linux__) && !defined __LINUX__
  #define __LINUX__
#endif
#if (defined __linux || defined __linux__) && !defined LINUX
  #define LINUX
#endif
#if defined FREEBSD && !defined __FreeBSD__
  #define __FreeBSD__
#endif
#if defined __LINUX__ || defined __FreeBSD__ || defined __OpenBSD__ || defined __APPLE__
  #include "sclinux.h"
#endif

#if defined __GNUC__
  #define GCC_VERSION (__GNUC__ * 10000 \
                       + __GNUC_MINOR__ * 100 \
                       + __GNUC_PATCHLEVEL__)
#endif

#if !defined HAVE_STDINT_H
  #define HAVE_STDINT_H 1
#endif
#if defined _WIN32 || defined __WIN32__ || defined WIN32
  #ifndef HAVE_I64
    #define HAVE_I64 1
  #endif
#endif

#if defined _LP64 || defined __LP64__ || defined WIN64 || defined _WIN64 || defined __x86_64__ || defined __aarch64__
  #if !defined __64BIT__
    #define __64BIT__ 1
  #endif
#else
  #if !defined __32BIT__
    #define __32BIT__ 1
  #endif
#endif

#if !defined HAVE_ALLOCA_H
  #if (defined __GNUC__ || defined __clang__) && !defined _WIN32
    #define HAVE_ALLOCA_H 1
  #endif
#endif
#if defined HAVE_ALLOCA_H && HAVE_ALLOCA_H
  #include <alloca.h>
#elif defined _WIN32
  #include <malloc.h>
  #if !defined alloca
    #define alloca(n)   _alloca(n)
  #endif
#endif

#if !defined arraysize
  #define arraysize(array)  (sizeof(array) / sizeof((array)[0]))
#endif

#if !defined assert_static
  #if defined __cplusplus
    #define assert_static(test) static_assert((test), "assert_static")
  #elif (defined __STDC_VERSION__ && __STDC_VERSION__ >= 201112L)
    #define assert_static(test) _Static_assert((test), "assert_static")
  #else
    #define assert_static(test) typedef char cd_static_assert_[(test) ? 1 : -1]
  #endif
#endif

#ifdef __cplusplus
extern "C" {
#endif

#if defined PAWN_DLL
  #if !defined AMX_NATIVE_CALL
    #define AMX_NATIVE_CALL __stdcall
  #endif
  #if !defined AMXAPI
    #define AMXAPI          __stdcall
  #endif
#endif

/* calling convention for native functions */
#if !defined AMX_NATIVE_CALL
  #if (defined _WIN32 || defined __WIN32__ || defined WIN32) && !defined __64BIT__
    #define AMX_NATIVE_CALL __cdecl
  #else
    #define AMX_NATIVE_CALL
  #endif
#endif

/* calling convention for all interface functions and callback functions */
#if !defined AMXAPI
  #if defined STDECL
    #define AMXAPI      __stdcall
  #elif defined CDECL || ((defined _WIN32 || defined __WIN32__ || defined WIN32) && !defined __64BIT__)
    #define AMXAPI      __cdecl
  #elif defined GCC_HASCLASSVISIBILITY
    #define AMXAPI __attribute__ ((visibility("default")))
  #else
    #define AMXAPI
  #endif
#endif

#if !defined AMXEXPORT
  #define AMXEXPORT
#endif

#define CUR_FILE_VERSION  11    /* current file version (supports Pawn 3.10+ v9/v10/v11 macro opcodes) */
#define MIN_FILE_VERSION  6     /* lowest supported file format version */
#define MIN_AMX_VERSION   10    /* minimum AMX version needed to support current file format */
#define MAX_FILE_VER_JIT  8     /* file version supported by the JIT */
#define MIN_AMX_VER_JIT   8     /* AMX version supported by the JIT */

/* SA-MP and open.mp always use 32-bit Pawn cells, even on 64-bit hosts */
#if !defined PAWN_CELL_SIZE
  #define PAWN_CELL_SIZE 32
#endif

#if PAWN_CELL_SIZE==16
  typedef uint16_t  ucell;
  typedef int16_t   cell;
#elif PAWN_CELL_SIZE==32
  typedef uint32_t  ucell;
  typedef int32_t   cell;
#elif PAWN_CELL_SIZE==64
  typedef uint64_t  ucell;
  typedef int64_t   cell;
#else
  #error Unsupported cell size (PAWN_CELL_SIZE)
#endif

#if defined __64BIT__ && PAWN_CELL_SIZE < 64
  #define AMX_DONT_RELOCATE
  #define AMX_WIDE_POINTERS
#elif defined __32BIT__ && PAWN_CELL_SIZE < 32
  #define AMX_DONT_RELOCATE
  #define AMX_WIDE_POINTERS
#endif

#define UNPACKEDMAX   (((ucell)1 << (sizeof(ucell)-1)*8) - 1)
#define UNLIMITED     (~1u >> 1)
#define STKMARGIN     ((cell)(16*sizeof(cell)))

struct tagAMX;
typedef cell (AMX_NATIVE_CALL *AMX_NATIVE)(struct tagAMX *amx, const cell *params);
typedef int (AMXAPI *AMX_CALLBACK)(struct tagAMX *amx, cell index,
                                   cell *result, const cell *params);
typedef int (AMXAPI *AMX_DEBUG)(struct tagAMX *amx);
typedef int (AMXAPI *AMX_IDLE)(struct tagAMX *amx, int AMXAPI Exec(struct tagAMX *, cell *, int));

/* CrashDetect / CrashDetect Plus VM extension hook types */
typedef int (AMXAPI *AMX_EXEC_ERROR)(struct tagAMX *amx, cell index, cell *retval, int error);
typedef int (AMXAPI *AMX_LCT_CTL)(struct tagAMX *amx, int option, int value);
typedef int (AMXAPI *AMX_ADDR_0_CTL)(struct tagAMX *amx, int option);

#if !defined _FAR
  #define _FAR
#endif

#if defined _MSC_VER
  #pragma warning(disable:4100)  /* unreferenced formal parameter */
  #pragma warning(disable:4103)  /* pragma pack in header */
  #pragma warning(disable:4127)  /* conditional expression is constant */
  #pragma warning(disable:4996)  /* POSIX name is deprecated */
#endif

#if defined __GNUC__
  #define PACKED        __attribute__((packed))
#else
  #define PACKED
#endif

#if !defined AMX_NO_ALIGN
  #if defined LINUX || defined __FreeBSD__
    #pragma pack(1)
  #elif defined MACOS && defined __MWERKS__
    #pragma options align=mac68k
  #else
    #pragma pack(push, 1)
  #endif
#endif

typedef struct tagAMX_NATIVE_INFO {
  const char _FAR *name PACKED;
  AMX_NATIVE func       PACKED;
} PACKED AMX_NATIVE_INFO;

#if !defined AMX_USERNUM
  #define AMX_USERNUM   4
#endif
#define sEXPMAX         19      /* maximum name length for file version <= 6 */
#ifndef sNAMEMAX
  #define sNAMEMAX      63      /* modern open.mp / Community Pawn maximum identifier length */
#endif

typedef struct tagAMX_FUNCSTUB {
  ucell address         PACKED;
  char name[sEXPMAX+1]  PACKED;
} PACKED AMX_FUNCSTUB;

typedef struct tagFUNCSTUBNT {
  ucell address         PACKED;
  uint32_t nameofs      PACKED;
} PACKED AMX_FUNCSTUBNT;

/* used when we don't yet know if this is AMX_FUNCSTUB or AMX_FUNCSTUBNT */
typedef struct tagFUNCPART {
  ucell address         PACKED;
} PACKED AMX_FUNCPART;

/* used on 64-bit when 8-byte native pointer occupies address + nameofs */
typedef struct tagFUNCWIDE {
  uintptr_t address     PACKED;
} PACKED AMX_FUNCWIDE;

typedef struct tagAMX {
  unsigned char _FAR *base PACKED; /* points to the AMX header plus the code, optionally also the data */
  unsigned char _FAR *data PACKED; /* points to separate data+stack+heap, may be NULL */
  AMX_CALLBACK callback PACKED;
  AMX_DEBUG debug       PACKED; /* debug callback */
  /* for external functions a few registers must be accessible from the outside */
  cell cip              PACKED; /* instruction pointer: relative to base + amxhdr->cod */
  cell frm              PACKED; /* stack frame base: relative to base + amxhdr->dat */
  cell hea              PACKED; /* top of the heap: relative to base + amxhdr->dat */
  cell hlw              PACKED; /* bottom of the heap: relative to base + amxhdr->dat */
  cell stk              PACKED; /* stack pointer: relative to base + amxhdr->dat */
  cell stp              PACKED; /* top of the stack: relative to base + amxhdr->dat */
  int flags             PACKED; /* current status, see amx_Flags() */
  /* user data */
  #if AMX_USERNUM > 0
  long usertags[AMX_USERNUM] PACKED;
  void _FAR *userdata[AMX_USERNUM] PACKED;
  #endif
  /* native functions can raise an error */
  int error             PACKED;
  /* passing parameters requires a "count" field */
  int paramcount;
  /* the sleep opcode needs to store the full AMX status */
  cell pri              PACKED;
  cell alt              PACKED;
  cell reset_stk        PACKED;
  cell reset_hea        PACKED;
  /* extra fields for increased performance */
  cell sysreq_d         PACKED; /* relocated address/value for the SYSREQ.D opcode */
  #if defined JIT
    int reloc_size      PACKED;
    long code_size      PACKED;
  #endif
} PACKED AMX;

typedef struct tagAMX_HEADER {
  int32_t size          PACKED; /* size of the "file" */
  uint16_t magic        PACKED; /* signature */
  char    file_version  PACKED; /* file format version */
  char    amx_version   PACKED; /* required version of the AMX */
  int16_t flags         PACKED;
  int16_t defsize       PACKED; /* size of a definition record */
  int32_t cod           PACKED; /* initial value of COD - code block */
  int32_t dat           PACKED; /* initial value of DAT - data block */
  int32_t hea           PACKED; /* initial value of HEA - start of the heap */
  int32_t stp           PACKED; /* initial value of STP - stack top */
  int32_t cip           PACKED; /* initial value of CIP - the instruction pointer */
  int32_t publics       PACKED; /* offset to the "public functions" table */
  int32_t natives       PACKED; /* offset to the "native functions" table */
  int32_t libraries     PACKED; /* offset to the table of libraries */
  int32_t pubvars       PACKED; /* the "public variables" table */
  int32_t tags          PACKED; /* the "public tagnames" table */
  int32_t nametable     PACKED; /* name table */
} PACKED AMX_HEADER;

typedef struct tagAMX_EXT_HOOKS {
  AMX_EXEC_ERROR exec_error;
  AMX_LCT_CTL long_call_ctl;
  AMX_ADDR_0_CTL address_naught_ctl;
} PACKED AMX_EXT_HOOKS;

#if !defined AMX_NO_ALIGN
  #if defined LINUX || defined __FreeBSD__
    #pragma pack()
  #elif defined MACOS && defined __MWERKS__
    #pragma options align=reset
  #else
    #pragma pack(pop)
  #endif
#endif

/* CrashDetect Plus zero-allocation unified fast call stack */
#define AMX_FAST_STACK_CAPACITY 512

enum {
  AMX_FAST_FRAME_PUBLIC = 0,
  AMX_FAST_FRAME_NATIVE = 1
};

typedef struct tagAMX_FAST_FRAME {
  AMX *amx;
  uintptr_t native_addr; /* non-zero for OP_SYSREQ_D when native index wasn't encoded directly */
  cell index;            /* public index or native index (-1 if only native_addr is known) */
  cell frm;              /* caller frame at point of call */
  cell cip;              /* caller cip at point of call */
  cell stk;              /* stack offset (params array) at native invocation */
  int kind;              /* AMX_FAST_FRAME_PUBLIC or AMX_FAST_FRAME_NATIVE */
} AMX_FAST_FRAME;

typedef struct tagAMX_FAST_STACK {
  int top;               /* total logical depth (may exceed AMX_FAST_STACK_CAPACITY on extreme recursion) */
  int track_natives;     /* 1 = track natives directly inside amx_Exec (fast_mode), 0 = tracked via OnCallback */
  cell last_max_hea;     /* high-water mark of hea observed in most recent amx_Exec */
  cell last_min_stk;     /* low-water mark of stk observed in most recent amx_Exec */
  cell cur_max_hea;      /* high-water mark of hea during currently executing amx_Exec */
  cell cur_min_stk;      /* low-water mark of stk during currently executing amx_Exec */
  AMX_FAST_FRAME frames[AMX_FAST_STACK_CAPACITY];
} AMX_FAST_STACK;

extern AMX_FAST_STACK g_amx_fast_stack;

#define AMX_MAGIC_16    0xf1e2
#define AMX_MAGIC_32    0xf1e0
#define AMX_MAGIC_64    0xf1e1
#if PAWN_CELL_SIZE==16
  #define AMX_MAGIC     AMX_MAGIC_16
#elif PAWN_CELL_SIZE==32
  #define AMX_MAGIC     AMX_MAGIC_32
#elif PAWN_CELL_SIZE==64
  #define AMX_MAGIC     AMX_MAGIC_64
#endif

#define USENAMETABLE(hdr) \
                        ((hdr)->defsize==sizeof(AMX_FUNCSTUBNT))
#define NUMENTRIES(hdr,field,nextfield) \
                        (unsigned)(((hdr)->nextfield - (hdr)->field) / (hdr)->defsize)
#define GETENTRY(hdr,table,index) \
                        (AMX_FUNCPART *)((unsigned char*)(hdr) + (unsigned)(hdr)->table + (unsigned)(index)*(hdr)->defsize)
#define GETENTRYNAME(hdr,entry) \
                        ( USENAMETABLE(hdr) \
                           ? (char *)((unsigned char*)(hdr) + (unsigned)((AMX_FUNCSTUBNT*)(entry))->nameofs) \
                           : ((AMX_FUNCSTUB*)(entry))->name )

#define CHARBITS        (8*sizeof(char))
#if PAWN_CELL_SIZE==16
  #define CHARMASK      (0xffffu << 8*(2-sizeof(char)))
#elif PAWN_CELL_SIZE==32
  #define CHARMASK      (0xffffffffuL << 8*(4-sizeof(char)))
#elif PAWN_CELL_SIZE==64
  #define CHARMASK      (0xffffffffffffffffuLL << 8*(8-sizeof(char)))
#else
  #error Unsupported cell size
#endif

enum {
  AMX_ERR_NONE,
  /* reserve the first 15 error codes for exit codes of the abstract machine */
  AMX_ERR_EXIT,         /* forced exit */
  AMX_ERR_ASSERT,       /* assertion failed */
  AMX_ERR_STACKERR,     /* stack/heap collision */
  AMX_ERR_BOUNDS,       /* index out of bounds */
  AMX_ERR_MEMACCESS,    /* invalid memory access */
  AMX_ERR_INVINSTR,     /* invalid instruction */
  AMX_ERR_STACKLOW,     /* stack underflow */
  AMX_ERR_HEAPLOW,      /* heap underflow */
  AMX_ERR_CALLBACK,     /* no callback, or invalid callback */
  AMX_ERR_NATIVE,       /* native function failed */
  AMX_ERR_DIVIDE,       /* divide by zero */
  AMX_ERR_SLEEP,        /* go into sleepmode - code can be restarted */
  AMX_ERR_INVSTATE,     /* invalid state for this access */

  AMX_ERR_MEMORY = 16,  /* out of memory */
  AMX_ERR_FORMAT,       /* invalid file format */
  AMX_ERR_VERSION,      /* file is for a newer version of the AMX */
  AMX_ERR_NOTFOUND,     /* function not found */
  AMX_ERR_INDEX,        /* invalid index parameter (bad entry point) */
  AMX_ERR_DEBUG,        /* debugger cannot run */
  AMX_ERR_INIT,         /* AMX not initialized (or doubly initialized) */
  AMX_ERR_USERDATA,     /* unable to set user data field (table full) */
  AMX_ERR_INIT_JIT,     /* cannot initialize the JIT */
  AMX_ERR_PARAMS,       /* parameter error */
  AMX_ERR_DOMAIN,       /* domain error, expression result does not fit in range */
  AMX_ERR_GENERAL,      /* general error (unknown or unspecific error) */
  AMX_ERR_ADDRESS_0,    /* wrote to address naught with error enabled */
};

#define AMX_FLAG_DEBUG      0x02   /* symbolic info. available */
#define AMX_FLAG_COMPACT    0x04   /* compact encoding */
#define AMX_FLAG_BYTEOPC    0x08   /* opcode is a byte (not a cell) / sleep flag */
#define AMX_FLAG_SLEEP      0x08
#define AMX_FLAG_NOCHECKS   0x10   /* no array bounds checking; no BREAK opcodes */
#define AMX_FLAG_NO_RELOC   0x200  /* no relocations done (64-bit wide pointers) */
#define AMX_FLAG_NO_SYSREQD 0x400  /* SYSREQ.D is NOT used */
#define AMX_FLAG_SYSREQN    0x800  /* script uses optimized SYSREQ.N opcode */
#define AMX_FLAG_NTVREG     0x1000 /* all native functions are registered */
#define AMX_FLAG_JITC       0x2000 /* abstract machine is JIT compiled */
#define AMX_FLAG_BROWSE     0x4000 /* busy browsing */
#define AMX_FLAG_RELOC      0x8000 /* jump/call addresses relocated */

#define AMX_EXEC_MAIN   (-1)    /* start at program entry point */
#define AMX_EXEC_CONT   (-2)    /* continue from last address */

#define AMX_USERTAG(a,b,c,d)    ((a) | ((b)<<8) | ((long)(c)<<16) | ((long)(d)<<24))

#if !defined AMX_COMPACTMARGIN
  #define AMX_COMPACTMARGIN 64
#endif

/* Long-call time control constants (Y-Less 0xFE / 0xFF #emit protocol) */
#define AMX_LCT_OPTION          1
#define AMX_LCT_SET_TIME        2
#define AMX_LCT_CHECK           3

#define AMX_LCT_OPTION_CURRENT  0  /* current time */
#define AMX_LCT_OPTION_ORIGINAL 1  /* original time */
#define AMX_LCT_OPTION_ACTIVE   2  /* is active? */
#define AMX_LCT_OPTION_RESTART  3  /* reset start time (restart the counter) */
#define AMX_LCT_OPTION_DISABLE  4  /* disable */
#define AMX_LCT_OPTION_ENABLE   5  /* enable */
#define AMX_LCT_OPTION_RESET    6  /* reset to original time */

#if PAWN_CELL_SIZE==32
  #define amx_ftoc(f)   ( * ((cell*)&(f)) )
  #define amx_ctof(c)   ( * ((float*)&(c)) )
#elif PAWN_CELL_SIZE==64
  #define amx_ftoc(f)   ( * ((cell*)&(f)) )
  #define amx_ctof(c)   ( * ((double*)&(c)) )
#else
  #error Unsupported cell size
#endif

#define amx_Address(amx,addr) \
                        (cell*)(((uintptr_t)((amx)->data ? (amx)->data : (amx)->base+(int)((AMX_HEADER *)(amx)->base)->dat)) + ((uintptr_t)(addr)))

#define amx_StrParam(amx,param,result)                                          \
    do {                                                                        \
      cell *amx_cstr_; int amx_length_;                                         \
      amx_GetAddr((amx), (param), &amx_cstr_);                                  \
      amx_StrLen(amx_cstr_, &amx_length_);                                      \
      if (amx_length_ > 0 &&                                                    \
          ((result) = (void*)alloca((amx_length_ + 1) * sizeof(*(result)))) != NULL) \
        amx_GetString((char*)(result), amx_cstr_, sizeof(*(result))>1, amx_length_ + 1); \
      else (result) = NULL;                                                     \
    } while (0)

#ifdef __cplusplus
#define amx_StrParamChar(amx, param, result)                                                                                   \
    do {                                                                                                                       \
        cell* amx_cstr_;                                                                                                       \
        int amx_length_;                                                                                                       \
        amx_GetAddr((amx), (param), &amx_cstr_);                                                                               \
        amx_StrLen(amx_cstr_, &amx_length_);                                                                                   \
        if (amx_length_ > 0 && ((result) = reinterpret_cast<char*>(alloca((amx_length_ + 1) * sizeof(*(result))))) != nullptr) \
            amx_GetString(reinterpret_cast<char*>(result), amx_cstr_, sizeof(*(result)) > 1, amx_length_ + 1);                 \
        else                                                                                                                   \
            (result) = const_cast<char*>("");                                                                                  \
    } while (0)
#endif

uint16_t * AMXAPI amx_Align16(uint16_t *v);
uint32_t * AMXAPI amx_Align32(uint32_t *v);
#if defined _I64_MAX || defined HAVE_I64 || defined INT64_MAX
  uint64_t * AMXAPI amx_Align64(uint64_t *v);
#endif
int AMXAPI amx_Allot(AMX *amx, int cells, cell *amx_addr, cell **phys_addr);
int AMXAPI amx_Callback(AMX *amx, cell index, cell *result, const cell *params);
int AMXAPI amx_Cleanup(AMX *amx);
int AMXAPI amx_Clone(AMX *amxClone, AMX *amxSource, void *data);
int AMXAPI amx_Exec(AMX *amx, cell *retval, int index);
int AMXAPI amx_FindNative(AMX *amx, const char *name, int *index);
int AMXAPI amx_FindPublic(AMX *amx, const char *funcname, int *index);
int AMXAPI amx_FindPubVar(AMX *amx, const char *varname, cell *amx_addr);
int AMXAPI amx_FindTagId(AMX *amx, cell tag_id, char *tagname);
int AMXAPI amx_Flags(AMX *amx, uint16_t *flags);
int AMXAPI amx_GetAddr(AMX *amx, cell amx_addr, cell **phys_addr);
int AMXAPI amx_GetExtHooks(AMX *amx, AMX_EXT_HOOKS **ext_hook);
int AMXAPI amx_GetNative(AMX *amx, int index, char *funcname);
int AMXAPI amx_GetNativeByIndex(const AMX *amx, int index, AMX_NATIVE_INFO *ret);
int AMXAPI amx_GetPublic(AMX *amx, int index, char *funcname);
int AMXAPI amx_GetPubVar(AMX *amx, int index, char *varname, cell *amx_addr);
int AMXAPI amx_GetString(char *dest, const cell *source, int use_wchar, size_t size);
int AMXAPI amx_GetTag(AMX *amx, int index, char *tagname, cell *tag_id);
int AMXAPI amx_GetUserData(AMX *amx, long tag, void **ptr);
int AMXAPI amx_Init(AMX *amx, void *program);
int AMXAPI amx_InitJIT(AMX *amx, void *reloc_table, void *native_code);
int AMXAPI amx_MakeAddr(AMX *amx, cell *phys_addr, cell *amx_addr);
int AMXAPI amx_MemInfo(AMX *amx, long *codesize, long *datasize, long *stackheap);
int AMXAPI amx_NameLength(AMX *amx, int *length);
AMX_NATIVE_INFO * AMXAPI amx_NativeInfo(const char *name, AMX_NATIVE func);
int AMXAPI amx_NumNatives(AMX *amx, int *number);
int AMXAPI amx_NumPublics(AMX *amx, int *number);
int AMXAPI amx_NumPubVars(AMX *amx, int *number);
int AMXAPI amx_NumTags(AMX *amx, int *number);
int AMXAPI amx_Push(AMX *amx, cell value);
int AMXAPI amx_PushArray(AMX *amx, cell *amx_addr, cell **phys_addr, const cell array[], int numcells);
int AMXAPI amx_PushString(AMX *amx, cell *amx_addr, cell **phys_addr, const char *string, int pack, int use_wchar);
int AMXAPI amx_PushStringLen(AMX *amx, cell *amx_addr, cell **phys_addr, const char *string, int length, int pack, int use_wchar);
int AMXAPI amx_RaiseError(AMX *amx, int error);
int AMXAPI amx_RaiseExecError(AMX *amx, cell index, cell *retval, int error);
int AMXAPI amx_Register(AMX *amx, const AMX_NATIVE_INFO *nativelist, int number);
int AMXAPI amx_Release(AMX *amx, cell amx_addr);
int AMXAPI amx_SetCallback(AMX *amx, AMX_CALLBACK callback);
int AMXAPI amx_SetDebugHook(AMX *amx, AMX_DEBUG debug);
int AMXAPI amx_SetDefaultExtHooks(AMX_EXT_HOOKS *ext_hook);
int AMXAPI amx_SetExtHooks(AMX *amx, AMX_EXT_HOOKS *ext_hook);
int AMXAPI amx_SetString(cell *dest, const char *source, int pack, int use_wchar, size_t size);
int AMXAPI amx_SetStringLen(cell *dest, const char *source, int length, int pack, int use_wchar, size_t size);
int AMXAPI amx_SetUserData(AMX *amx, long tag, void *ptr);
int AMXAPI amx_StrLen(const cell *cstring, int *length);
int AMXAPI amx_StrSize(const cell *cstr, int *length);
int AMXAPI amx_UTF8Check(const char *string, int *length);
int AMXAPI amx_UTF8Get(const char *string, const char **endptr, cell *value);
int AMXAPI amx_UTF8Len(const cell *cstr, int *length);
int AMXAPI amx_UTF8Put(char *string, char **endptr, int maxchars, cell value);

#if PAWN_CELL_SIZE==16
  void amx_Swap16(uint16_t *v);
  #define amx_AlignCell(v) amx_Align16(v)
#elif PAWN_CELL_SIZE==32
  void amx_Swap32(uint32_t *v);
  #define amx_AlignCell(v) amx_Align32(v)
#elif PAWN_CELL_SIZE==64 && (defined _I64_MAX || defined HAVE_I64 || defined INT64_MAX)
  void amx_Swap64(uint64_t *v);
  #define amx_AlignCell(v) amx_Align64(v)
#else
  #error Unsupported cell size
#endif

#define amx_RegisterFunc(amx, name, func) \
  amx_Register((amx), amx_NativeInfo((name),(func)), 1)

#ifdef __cplusplus
}
#endif

/* Global watchdog signal for pending long call time warning (sampled on backward jumps & calls) */
#if defined(__cplusplus)
  #include <atomic>
  extern "C" {
    extern std::atomic<int> g_cdplus_lct_pending;
  }
  static_assert(sizeof(std::atomic<int>) == sizeof(int) && std::atomic<int>::is_always_lock_free,
                "std::atomic<int> ABI must match int and be lock-free");
  inline int cd_lct_pending_load() {
    return g_cdplus_lct_pending.load(std::memory_order_relaxed);
  }
  inline void cd_lct_pending_store(int v) {
    g_cdplus_lct_pending.store(v, std::memory_order_release);
  }
  #define CD_LCT_PENDING_LOAD() cd_lct_pending_load()
  #define CD_SET_LCT_PENDING(v) cd_lct_pending_store(v)
#elif defined(__GNUC__) || defined(__clang__)
  extern int g_cdplus_lct_pending;
  #define CD_LCT_PENDING_LOAD() __atomic_load_n(&g_cdplus_lct_pending, __ATOMIC_RELAXED)
  #define CD_SET_LCT_PENDING(v) __atomic_store_n(&g_cdplus_lct_pending, (v), __ATOMIC_RELEASE)
#elif defined(_MSC_VER)
  extern volatile int g_cdplus_lct_pending;
  #if defined(_M_IX86) || defined(_M_X64) || defined(_M_ARM) || defined(_M_ARM64)
    int __iso_volatile_load32(const volatile int *);
    void __iso_volatile_store32(volatile int *, int);
    #pragma intrinsic(__iso_volatile_load32)
    #pragma intrinsic(__iso_volatile_store32)
    #define CD_LCT_PENDING_LOAD() __iso_volatile_load32((const volatile int *)&g_cdplus_lct_pending)
    #define CD_SET_LCT_PENDING(v) __iso_volatile_store32((volatile int *)&g_cdplus_lct_pending, (v))
  #else
    #define CD_LCT_PENDING_LOAD() (g_cdplus_lct_pending)
    #define CD_SET_LCT_PENDING(v) do { g_cdplus_lct_pending = (v); } while(0)
  #endif
#else
  extern volatile int g_cdplus_lct_pending;
  #define CD_LCT_PENDING_LOAD() (g_cdplus_lct_pending)
  #define CD_SET_LCT_PENDING(v) do { g_cdplus_lct_pending = (v); } while(0)
#endif

#endif /* AMX_H_INCLUDED */
