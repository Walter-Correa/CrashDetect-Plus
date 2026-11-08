/*  Pawn Abstract Machine (for the Pawn language)
 *
 *  Copyright (c) ITB CompuPhase, 1997-2006
 *  Modified for CrashDetect (Zeex, Y-Less) and CrashDetect Plus:
 *  - Supports both classic SA-MP .amx (v6..8, SYSREQ.D) and modern open.mp .amx (v9+, SYSREQ.N & -O2 macro ops)
 *  - Full 32-bit (x86) and 64-bit (x64 AMX_DONT_RELOCATE + AMX_WIDE_POINTERS) VM execution
 *  - Zero-allocation fast native call tracking (SYSREQ.C, SYSREQ.N, SYSREQ.D, SYSREQ.PRI)
 *  - Register-local stack/heap high-watermark telemetry & low-overhead bitwise long_call_time sampling
 *  - Full Y-Less 0xFE/0xFF LCTRL/SCTRL compatibility and expanded address-naught protection
 *  - Zero AMX::userdata slot consumption via default ext_hooks fallback
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

#ifndef WIN32_LEAN_AND_MEAN
  #define WIN32_LEAN_AND_MEAN
#endif

#include <assert.h>
#include <limits.h>
#include <stdarg.h>
#include <stddef.h>
#include <string.h>
#include <wchar.h>
#include "osdefs.h"
#if defined LINUX || defined __FreeBSD__ || defined __OpenBSD__ || defined __APPLE__
  #include "sclinux.h"
  #if !defined AMX_NODYNALOAD
    #define AMX_NODYNALOAD 1
  #endif
#endif
#include "amx.h"
#if (defined _Windows && !defined AMX_NODYNALOAD)
  #define AMX_NODYNALOAD 1
#endif

/* Global zero-allocation fast stack & watermarks for CrashDetect Plus */
AMX_FAST_STACK g_amx_fast_stack = { 0, 1, 0, 0, 0, 0, { { 0 } } };
static AMX_EXT_HOOKS *g_default_ext_hooks = NULL;

static void checkLongCallTime(AMX *amx, AMX_LCT_CTL long_call_ctl, cell cip_off, cell frm, cell hea, cell stk)
{
  if (long_call_ctl != NULL) {
    cell tmp_cip = amx->cip;
    cell tmp_frm = amx->frm;
    cell tmp_hea = amx->hea;
    cell tmp_stk = amx->stk;
    amx->cip = cip_off;
    amx->frm = frm;
    amx->hea = hea;
    amx->stk = stk;
    if (stk < g_amx_fast_stack.cur_min_stk) g_amx_fast_stack.cur_min_stk = stk;
    if (hea > g_amx_fast_stack.cur_max_hea) g_amx_fast_stack.cur_max_hea = hea;
    g_amx_fast_stack.last_max_hea = g_amx_fast_stack.cur_max_hea;
    g_amx_fast_stack.last_min_stk = g_amx_fast_stack.cur_min_stk;
    long_call_ctl(amx, AMX_LCT_CHECK, 0);
    amx->cip = tmp_cip;
    amx->frm = tmp_frm;
    amx->hea = tmp_hea;
    amx->stk = tmp_stk;
  }
}

#if defined(__GNUC__) || defined(__clang__)
  #define CD_UNLIKELY(x) __builtin_expect(!!(x), 0)
#else
  #define CD_UNLIKELY(x) (x)
#endif

#define CHECK_LCT_CALL(back_cells) \
  do { \
    if (CD_UNLIKELY(CD_LCT_PENDING_LOAD()) && long_call_ctl != NULL) { \
      checkLongCallTime(amx, long_call_ctl, _R(data, stk) - (cell)((back_cells) * sizeof(cell)), frm, hea, stk); \
    } \
  } while (0)

#define CHECK_LCT_JUMP(dest) \
  do { \
    if ((cell *)(dest) <= cip) { \
      if (CD_UNLIKELY(CD_LCT_PENDING_LOAD()) && long_call_ctl != NULL) { \
        checkLongCallTime(amx, long_call_ctl, (cell)((unsigned char *)cip - code), frm, hea, stk); \
      } \
    } \
  } while (0)

#define CD_COND_JUMP(cond) \
  do { \
    if (cond) { \
      cip = JUMPABS(code, cip); \
    } else { \
      cip = (cell *)((unsigned char *)cip + sizeof(cell)); \
    } \
  } while (0)

#define CD_WATERMARK() \
  do { \
    if (stk < g_amx_fast_stack.cur_min_stk) g_amx_fast_stack.cur_min_stk = stk; \
    if (hea > g_amx_fast_stack.cur_max_hea) g_amx_fast_stack.cur_max_hea = hea; \
  } while (0)

#define CD_TRACK_STK() ((void)0)
#define CD_TRACK_HEA() ((void)0)
#define CD_SAVE_WATERMARKS() \
  do { \
    CD_WATERMARK(); \
    g_amx_fast_stack.last_max_hea = g_amx_fast_stack.cur_max_hea; \
    g_amx_fast_stack.last_min_stk = g_amx_fast_stack.cur_min_stk; \
  } while (0)

#define CD_NATIVE_ENTER(nidx, naddr) \
  CD_WATERMARK(); \
  int _cd_prev_top = g_amx_fast_stack.top; \
  if (g_amx_fast_stack.track_natives) { \
    if ((unsigned)_cd_prev_top < AMX_FAST_STACK_CAPACITY) { \
      AMX_FAST_FRAME *_cdf = &g_amx_fast_stack.frames[_cd_prev_top]; \
      _cdf->amx = amx; \
      _cdf->native_addr = (uintptr_t)(naddr); \
      _cdf->index = (cell)(nidx); \
      _cdf->frm = frm; \
      _cdf->cip = amx->cip; \
      _cdf->stk = stk; \
      _cdf->kind = AMX_FAST_FRAME_NATIVE; \
    } \
    g_amx_fast_stack.top = _cd_prev_top + 1; \
  }

#define CD_NATIVE_LEAVE() \
  do { \
    if (g_amx_fast_stack.track_natives) { \
      g_amx_fast_stack.top = _cd_prev_top; \
    } \
  } while (0)

typedef enum {
  OP_NONE,              /* invalid opcode */
  OP_LOAD_PRI,
  OP_LOAD_ALT,
  OP_LOAD_S_PRI,
  OP_LOAD_S_ALT,
  OP_LREF_PRI,
  OP_LREF_ALT,
  OP_LREF_S_PRI,
  OP_LREF_S_ALT,
  OP_LOAD_I,
  OP_LODB_I,
  OP_CONST_PRI,
  OP_CONST_ALT,
  OP_ADDR_PRI,
  OP_ADDR_ALT,
  OP_STOR_PRI,
  OP_STOR_ALT,
  OP_STOR_S_PRI,
  OP_STOR_S_ALT,
  OP_SREF_PRI,
  OP_SREF_ALT,
  OP_SREF_S_PRI,
  OP_SREF_S_ALT,
  OP_STOR_I,
  OP_STRB_I,
  OP_LIDX,
  OP_LIDX_B,
  OP_IDXADDR,
  OP_IDXADDR_B,
  OP_ALIGN_PRI,
  OP_ALIGN_ALT,
  OP_LCTRL,
  OP_SCTRL,
  OP_MOVE_PRI,
  OP_MOVE_ALT,
  OP_XCHG,
  OP_PUSH_PRI,
  OP_PUSH_ALT,
  OP_PUSH_R,
  OP_PUSH_C,
  OP_PUSH,
  OP_PUSH_S,
  OP_POP_PRI,
  OP_POP_ALT,
  OP_STACK,
  OP_HEAP,
  OP_PROC,
  OP_RET,
  OP_RETN,
  OP_CALL,
  OP_CALL_PRI,
  OP_JUMP,
  OP_JREL,
  OP_JZER,
  OP_JNZ,
  OP_JEQ,
  OP_JNEQ,
  OP_JLESS,
  OP_JLEQ,
  OP_JGRTR,
  OP_JGEQ,
  OP_JSLESS,
  OP_JSLEQ,
  OP_JSGRTR,
  OP_JSGEQ,
  OP_SHL,
  OP_SHR,
  OP_SSHR,
  OP_SHL_C_PRI,
  OP_SHL_C_ALT,
  OP_SHR_C_PRI,
  OP_SHR_C_ALT,
  OP_SMUL,
  OP_SDIV,
  OP_SDIV_ALT,
  OP_UMUL,
  OP_UDIV,
  OP_UDIV_ALT,
  OP_ADD,
  OP_SUB,
  OP_SUB_ALT,
  OP_AND,
  OP_OR,
  OP_XOR,
  OP_NOT,
  OP_NEG,
  OP_INVERT,
  OP_ADD_C,
  OP_SMUL_C,
  OP_ZERO_PRI,
  OP_ZERO_ALT,
  OP_ZERO,
  OP_ZERO_S,
  OP_SIGN_PRI,
  OP_SIGN_ALT,
  OP_EQ,
  OP_NEQ,
  OP_LESS,
  OP_LEQ,
  OP_GRTR,
  OP_GEQ,
  OP_SLESS,
  OP_SLEQ,
  OP_SGRTR,
  OP_SGEQ,
  OP_EQ_C_PRI,
  OP_EQ_C_ALT,
  OP_INC_PRI,
  OP_INC_ALT,
  OP_INC,
  OP_INC_S,
  OP_INC_I,
  OP_DEC_PRI,
  OP_DEC_ALT,
  OP_DEC,
  OP_DEC_S,
  OP_DEC_I,
  OP_MOVS,
  OP_CMPS,
  OP_FILL,
  OP_HALT,
  OP_BOUNDS,
  OP_SYSREQ_PRI,
  OP_SYSREQ_C,
  OP_FILE,
  OP_LINE,
  OP_SYMBOL,
  OP_SRANGE,
  OP_JUMP_PRI,
  OP_SWITCH,
  OP_CASETBL,
  OP_SWAP_PRI,
  OP_SWAP_ALT,
  OP_PUSH_ADR,
  OP_NOP,
  OP_SYSREQ_N,          /* 135: OP_SYSREQ_D in file_version <= 8, OP_SYSREQ_N in file_version >= 9 */
  OP_SYMTAG,
  OP_BREAK,
  OP_PUSH2_C,
  OP_PUSH2,
  OP_PUSH2_S,
  OP_PUSH2_ADR,
  OP_PUSH3_C,
  OP_PUSH3,
  OP_PUSH3_S,
  OP_PUSH3_ADR,
  OP_PUSH4_C,
  OP_PUSH4,
  OP_PUSH4_S,
  OP_PUSH4_ADR,
  OP_PUSH5_C,
  OP_PUSH5,
  OP_PUSH5_S,
  OP_PUSH5_ADR,
  OP_LOAD_BOTH,
  OP_LOAD_S_BOTH,
  OP_CONST,
  OP_CONST_S,
  /* placeholders */
  _OP_SYSREQ_D,
  _OP_SYSREQ_ND,
  OP_NUM_OPCODES
} OPCODE;

#define OP_PUSHADDR OP_PUSH_ADR
#define OP_SYSREQ_D OP_SYSREQ_N

#if !defined NDEBUG
static int check_endian(void)
{
  uint16_t val = 0x00ff;
  unsigned char *ptr = (unsigned char *)&val;
  assert(*ptr == 0xff || *ptr == 0x00);
  #if BYTE_ORDER==BIG_ENDIAN
    return *ptr == 0x00;
  #else
    return *ptr == 0xff;
  #endif
}
#endif

#if BYTE_ORDER==BIG_ENDIAN || PAWN_CELL_SIZE==16
void amx_Swap16(uint16_t *v)
{
  unsigned char *s = (unsigned char *)v;
  unsigned char t = s[0];
  s[0] = s[1];
  s[1] = t;
}
#endif

#if BYTE_ORDER==BIG_ENDIAN || PAWN_CELL_SIZE==32
void amx_Swap32(uint32_t *v)
{
  unsigned char *s = (unsigned char *)v;
  unsigned char t = s[0];
  s[0] = s[3];
  s[3] = t;
  t = s[1];
  s[1] = s[2];
  s[2] = t;
}
#endif

#if (BYTE_ORDER==BIG_ENDIAN || PAWN_CELL_SIZE==64) && (defined _I64_MAX || defined HAVE_I64 || defined INT64_MAX)
void amx_Swap64(uint64_t *v)
{
  unsigned char *s = (unsigned char *)v;
  unsigned char t;
  t = s[0]; s[0] = s[7]; s[7] = t;
  t = s[1]; s[1] = s[6]; s[6] = t;
  t = s[2]; s[2] = s[5]; s[5] = t;
  t = s[3]; s[3] = s[4]; s[4] = t;
}
#endif

uint16_t * AMXAPI amx_Align16(uint16_t *v)
{
  assert_static(sizeof(*v) == 2);
  assert(check_endian());
  #if BYTE_ORDER==BIG_ENDIAN
    amx_Swap16(v);
  #endif
  return v;
}

uint32_t * AMXAPI amx_Align32(uint32_t *v)
{
  assert_static(sizeof(*v) == 4);
  assert(check_endian());
  #if BYTE_ORDER==BIG_ENDIAN
    amx_Swap32(v);
  #endif
  return v;
}

#if defined _I64_MAX || defined HAVE_I64 || defined INT64_MAX
uint64_t * AMXAPI amx_Align64(uint64_t *v)
{
  assert(sizeof(*v) == 8);
  assert(check_endian());
  #if BYTE_ORDER==BIG_ENDIAN
    amx_Swap64(v);
  #endif
  return v;
}
#endif

#if PAWN_CELL_SIZE==16
  #define swapcell  amx_Swap16
#elif PAWN_CELL_SIZE==32
  #define swapcell  amx_Swap32
#elif PAWN_CELL_SIZE==64 && (defined _I64_MAX || defined HAVE_I64 || defined INT64_MAX)
  #define swapcell  amx_Swap64
#else
  #error Unsupported cell size
#endif

int AMXAPI amx_Flags(AMX *amx, uint16_t *flags)
{
  AMX_HEADER *hdr;

  *flags = 0;
  if (amx == NULL)
    return AMX_ERR_FORMAT;
  hdr = (AMX_HEADER *)amx->base;
  if (hdr->magic != AMX_MAGIC)
    return AMX_ERR_FORMAT;
  if (hdr->file_version > CUR_FILE_VERSION || hdr->amx_version < MIN_FILE_VERSION)
    return AMX_ERR_VERSION;
  if (hdr->file_version == 9 && hdr->amx_version == 9)
    return AMX_ERR_VERSION;
  *flags = (uint16_t)hdr->flags;
  return AMX_ERR_NONE;
}

#if (defined __GNUC__ && !defined __MINGW32__) && !defined __64BIT__
  static cell s_reloc_sysreq_c = 0;
  static cell s_reloc_sysreq_n = 0;
  static cell s_reloc_sysreq_nd = 0;
#endif

int AMXAPI amx_Callback(AMX *amx, cell index, cell *result, const cell *params)
{
  AMX_HEADER *hdr;
  AMX_FUNCPART *func;
  AMX_NATIVE f;

  assert(amx != NULL);
  hdr = (AMX_HEADER *)amx->base;
  assert(hdr != NULL);
  assert(hdr->magic == AMX_MAGIC);
  assert(hdr->natives <= hdr->libraries);
  if (index < 0 || index >= (cell)NUMENTRIES(hdr, natives, libraries))
    return AMX_ERR_NOTFOUND;

  func = GETENTRY(hdr, natives, index);
  f = (AMX_NATIVE)((AMX_FUNCWIDE *)func)->address;
  if (f == NULL)
    return AMX_ERR_NOTFOUND;

  #if !defined AMX_WIDE_POINTERS && !defined AMX_DONT_RELOCATE
    /* 32-bit SYSREQ.D & Pawn 3.10 _OP_SYSREQ_ND bytecode self-patching when enabled */
    if (amx->sysreq_d != 0) {
      unsigned char *code = amx->base + (uintptr_t)hdr->cod;
      if (hdr->file_version >= 9) {
        #if (defined __GNUC__ && !defined __MINGW32__) && !defined __64BIT__
          cell op_c = s_reloc_sysreq_c;
          cell op_n = s_reloc_sysreq_n;
          cell op_nd = s_reloc_sysreq_nd;
        #else
          cell op_c = OP_SYSREQ_C;
          cell op_n = OP_SYSREQ_N;
          cell op_nd = _OP_SYSREQ_ND;
        #endif
        if (amx->cip >= (cell)(3 * sizeof(cell))) {
          cell *op3 = (cell *)(code + (uintptr_t)amx->cip) - 3;
          if (op3[0] == op_n && op3[1] == index) {
            op3[0] = op_nd;
            op3[1] = (cell)(uintptr_t)f;
          } else if (op3[1] == op_c && op3[2] == index) {
            op3[1] = amx->sysreq_d;
            op3[2] = (cell)(uintptr_t)f;
          }
        } else if (amx->cip >= (cell)(2 * sizeof(cell))) {
          cell *op2 = (cell *)(code + (uintptr_t)amx->cip) - 2;
          if (op2[0] == op_c && op2[1] == index) {
            op2[0] = amx->sysreq_d;
            op2[1] = (cell)(uintptr_t)f;
          }
        }
      } else if (amx->cip >= (cell)(2 * sizeof(cell))) {
        cell *op_ptr = (cell *)(code + (uintptr_t)amx->cip) - 2;
        if (op_ptr[1] == index) {
          op_ptr[0] = amx->sysreq_d;
          op_ptr[1] = (cell)(uintptr_t)f;
        }
      }
    }
  #endif

  amx->error = AMX_ERR_NONE;
  *result = f(amx, params);
  return amx->error;
}

#if PAWN_CELL_SIZE==16 || defined AMX_DONT_RELOCATE
  #define JUMPABS(base, ip)     ((cell *)((base) + (uintptr_t)(*(ucell *)(ip))))
  #define RELOC_ABS(base, off)
  #define RELOC_VALUE(base, v)  (v)
#else
  #define JUMPABS(base, ip)     ((cell *)(uintptr_t)(*(ucell *)(ip)))
  #define RELOC_ABS(base, off)  (*(ucell *)((base) + (uintptr_t)(off)) += (ucell)(uintptr_t)(base))
  #define RELOC_VALUE(base, v)  ((v) + ((ucell)(uintptr_t)(base)))
#endif

#define DBGPARAM(v)     ( (v) = *(cell *)(code + (uintptr_t)cip), cip += sizeof(cell) )

static int amx_BrowseRelocate(AMX *amx)
{
  AMX_HEADER *hdr;
  unsigned char *code;
  cell cip;
  long codesize;
  OPCODE op;
  int sysreq_flg = 0;
  int is_v9;
  #if (defined __GNUC__ && !defined __MINGW32__) && !defined __64BIT__
    cell *opcode_list = NULL;
  #endif

  assert(amx != NULL);
  hdr = (AMX_HEADER *)amx->base;
  assert(hdr != NULL);
  assert(hdr->magic == AMX_MAGIC);
  code = amx->base + (uintptr_t)hdr->cod;
  codesize = hdr->dat - hdr->cod;
  is_v9 = (hdr->file_version >= 9);
  amx->flags |= AMX_FLAG_BROWSE;

  assert_static(OP_PUSH_PRI == 36);
  assert_static(OP_PROC == 46);
  assert_static(OP_SHL == 65);
  assert_static(OP_SMUL == 72);
  assert_static(OP_EQ == 95);
  assert_static(OP_INC_PRI == 107);
  assert_static(OP_MOVS == 117);
  assert_static(OP_SYMBOL == 126);
  assert_static(OP_LOAD_BOTH == 154);

  #if (defined __GNUC__ && !defined __MINGW32__) && !defined __64BIT__
    amx_Exec(amx, (cell *)(void *)&opcode_list, 0);
    s_reloc_sysreq_c = opcode_list[OP_SYSREQ_C];
    s_reloc_sysreq_n = opcode_list[OP_SYSREQ_N];
    s_reloc_sysreq_nd = opcode_list[_OP_SYSREQ_ND];
  #endif

  amx->sysreq_d = 0;
  #if !defined AMX_WIDE_POINTERS && !defined AMX_DONT_RELOCATE
    #if (defined __GNUC__ && !defined __MINGW32__) && !defined __64BIT__
      amx->sysreq_d = is_v9 ? opcode_list[_OP_SYSREQ_D] : opcode_list[OP_SYSREQ_D];
    #else
      amx->sysreq_d = is_v9 ? _OP_SYSREQ_D : OP_SYSREQ_D;
    #endif
  #endif

  for (cip = 0; cip < codesize; ) {
    op = (OPCODE) *(ucell *)(code + (uintptr_t)cip);
    if ((unsigned)op >= OP_NUM_OPCODES || (!is_v9 && op > OP_BREAK)) {
      amx->flags &= ~AMX_FLAG_BROWSE;
      return AMX_ERR_INVINSTR;
    }
    #if (defined __GNUC__ && !defined __MINGW32__) && !defined __64BIT__
      *(cell *)(code + (uintptr_t)cip) = opcode_list[op];
    #endif
    cip += sizeof(cell);
    switch (op) {
    case OP_PUSH5_C:
    case OP_PUSH5:
    case OP_PUSH5_S:
    case OP_PUSH5_ADR:
      cip += sizeof(cell) * 5;
      break;

    case OP_PUSH4_C:
    case OP_PUSH4:
    case OP_PUSH4_S:
    case OP_PUSH4_ADR:
      cip += sizeof(cell) * 4;
      break;

    case OP_PUSH3_C:
    case OP_PUSH3:
    case OP_PUSH3_S:
    case OP_PUSH3_ADR:
      cip += sizeof(cell) * 3;
      break;

    case OP_PUSH2_C:
    case OP_PUSH2:
    case OP_PUSH2_S:
    case OP_PUSH2_ADR:
    case OP_LOAD_BOTH:
    case OP_LOAD_S_BOTH:
    case OP_CONST:
    case OP_CONST_S:
      cip += sizeof(cell) * 2;
      break;

    case OP_LOAD_PRI:
    case OP_LOAD_ALT:
    case OP_LOAD_S_PRI:
    case OP_LOAD_S_ALT:
    case OP_LREF_PRI:
    case OP_LREF_ALT:
    case OP_LREF_S_PRI:
    case OP_LREF_S_ALT:
    case OP_LODB_I:
    case OP_CONST_PRI:
    case OP_CONST_ALT:
    case OP_ADDR_PRI:
    case OP_ADDR_ALT:
    case OP_STOR_PRI:
    case OP_STOR_ALT:
    case OP_STOR_S_PRI:
    case OP_STOR_S_ALT:
    case OP_SREF_PRI:
    case OP_SREF_ALT:
    case OP_SREF_S_PRI:
    case OP_SREF_S_ALT:
    case OP_STRB_I:
    case OP_LIDX_B:
    case OP_IDXADDR_B:
    case OP_ALIGN_PRI:
    case OP_ALIGN_ALT:
    case OP_LCTRL:
    case OP_SCTRL:
    case OP_PUSH_R:
    case OP_PUSH_C:
    case OP_PUSH:
    case OP_PUSH_S:
    case OP_STACK:
    case OP_HEAP:
    case OP_JREL:
    case OP_SHL_C_PRI:
    case OP_SHL_C_ALT:
    case OP_SHR_C_PRI:
    case OP_SHR_C_ALT:
    case OP_ADD_C:
    case OP_SMUL_C:
    case OP_ZERO:
    case OP_ZERO_S:
    case OP_EQ_C_PRI:
    case OP_EQ_C_ALT:
    case OP_INC:
    case OP_INC_S:
    case OP_DEC:
    case OP_DEC_S:
    case OP_MOVS:
    case OP_CMPS:
    case OP_FILL:
    case OP_HALT:
    case OP_BOUNDS:
    case OP_PUSH_ADR:
      cip += sizeof(cell);
      break;

    case OP_LOAD_I:
    case OP_STOR_I:
    case OP_LIDX:
    case OP_IDXADDR:
    case OP_MOVE_PRI:
    case OP_MOVE_ALT:
    case OP_XCHG:
    case OP_PUSH_PRI:
    case OP_PUSH_ALT:
    case OP_POP_PRI:
    case OP_POP_ALT:
    case OP_PROC:
    case OP_RET:
    case OP_RETN:
    case OP_CALL_PRI:
    case OP_SHL:
    case OP_SHR:
    case OP_SSHR:
    case OP_SMUL:
    case OP_SDIV:
    case OP_SDIV_ALT:
    case OP_UMUL:
    case OP_UDIV:
    case OP_UDIV_ALT:
    case OP_ADD:
    case OP_SUB:
    case OP_SUB_ALT:
    case OP_AND:
    case OP_OR:
    case OP_XOR:
    case OP_NOT:
    case OP_NEG:
    case OP_INVERT:
    case OP_ZERO_PRI:
    case OP_ZERO_ALT:
    case OP_SIGN_PRI:
    case OP_SIGN_ALT:
    case OP_EQ:
    case OP_NEQ:
    case OP_LESS:
    case OP_LEQ:
    case OP_GRTR:
    case OP_GEQ:
    case OP_SLESS:
    case OP_SLEQ:
    case OP_SGRTR:
    case OP_SGEQ:
    case OP_INC_PRI:
    case OP_INC_ALT:
    case OP_INC_I:
    case OP_DEC_PRI:
    case OP_DEC_ALT:
    case OP_DEC_I:
    case OP_JUMP_PRI:
    case OP_SWAP_PRI:
    case OP_SWAP_ALT:
    case OP_NOP:
    case OP_BREAK:
      break;

    case OP_SYSREQ_PRI:
      amx->sysreq_d = 0; /* indirect native calls disable SYSREQ.D patching */
      break;

    case OP_CALL:
    case OP_JUMP:
    case OP_JZER:
    case OP_JNZ:
    case OP_JEQ:
    case OP_JNEQ:
    case OP_JLESS:
    case OP_JLEQ:
    case OP_JGRTR:
    case OP_JGEQ:
    case OP_JSLESS:
    case OP_JSLEQ:
    case OP_JSGRTR:
    case OP_JSGEQ:
    case OP_SWITCH:
      RELOC_ABS(code, cip);
      cip += sizeof(cell);
      break;

    case OP_SYSREQ_C:
      cip += sizeof(cell);
      sysreq_flg |= 0x01;
      break;

    case OP_SYSREQ_N:
      if (is_v9) {
        cip += sizeof(cell) * 2;
        sysreq_flg |= 0x02;
      } else {
        cip += sizeof(cell);
      }
      break;

    case OP_FILE:
    case OP_SYMBOL: {
      cell num;
      DBGPARAM(num);
      cip += num;
      break;
    }
    case OP_LINE:
    case OP_SRANGE:
      cip += 2 * sizeof(cell);
      break;
    case OP_SYMTAG:
      cip += sizeof(cell);
      break;
    case OP_CASETBL: {
      cell num;
      int i;
      DBGPARAM(num);
      for (i = 0; i <= num; i++)
        RELOC_ABS(code, cip + 2 * i * sizeof(cell));
      cip += (2 * num + 1) * sizeof(cell);
      break;
    }
    default:
      amx->flags &= ~AMX_FLAG_BROWSE;
      return AMX_ERR_INVINSTR;
    }
  }

  amx->flags &= ~AMX_FLAG_BROWSE;
  amx->flags |= AMX_FLAG_RELOC;
  #if defined AMX_DONT_RELOCATE
    amx->flags |= AMX_FLAG_NO_RELOC;
    amx->flags |= AMX_FLAG_NO_SYSREQD;
  #endif
  if (sysreq_flg & 0x02)
    amx->flags |= AMX_FLAG_SYSREQN;
  if (amx->sysreq_d == 0)
    amx->flags |= AMX_FLAG_NO_SYSREQD;
  return AMX_ERR_NONE;
}

#if AMX_COMPACTMARGIN > 2
static void expand(unsigned char *code, long codesize, long memsize)
{
  ucell c;
  struct {
    long memloc;
    ucell c;
  } spare[AMX_COMPACTMARGIN];
  int sh = 0, st = 0, sc = 0;
  int shift;

  assert(memsize % sizeof(cell) == 0);
  while (codesize > 0) {
    c = 0;
    shift = 0;
    do {
      codesize--;
      assert(shift < (int)(8 * sizeof(cell)));
      assert(shift > 0 || (code[(size_t)codesize] & 0x80) == 0);
      c |= (ucell)(code[(size_t)codesize] & 0x7f) << shift;
      shift += 7;
    } while (codesize > 0 && (code[(size_t)codesize - 1] & 0x80) != 0);
    if ((code[(size_t)codesize] & 0x40) != 0) {
      while (shift < (int)(8 * sizeof(cell))) {
        c |= (ucell)0xff << shift;
        shift += 8;
      }
    }
    while (sc && (spare[sh].memloc > codesize)) {
      *(ucell *)(code + (uintptr_t)spare[sh].memloc) = spare[sh].c;
      sh = (sh + 1) % AMX_COMPACTMARGIN;
      sc--;
    }
    memsize -= sizeof(cell);
    assert(memsize >= 0);
    if ((memsize > codesize) || ((memsize == codesize) && (memsize == 0))) {
      *(ucell *)(code + (size_t)memsize) = c;
    } else {
      assert(sc < AMX_COMPACTMARGIN);
      spare[st].memloc = memsize;
      spare[st].c = c;
      st = (st + 1) % AMX_COMPACTMARGIN;
      sc++;
    }
  }
  assert(memsize == 0);
}
#endif

int AMXAPI amx_Init(AMX *amx, void *program)
{
  AMX_HEADER *hdr;
  int err;
  unsigned char *data;

  if ((amx->flags & AMX_FLAG_RELOC) != 0)
    return AMX_ERR_INIT;

  hdr = (AMX_HEADER *)program;
  assert(check_endian());
  #if BYTE_ORDER==BIG_ENDIAN
    amx_Align32((uint32_t*)&hdr->size);
    amx_Align16(&hdr->magic);
    amx_Align16((uint16_t*)&hdr->flags);
    amx_Align16((uint16_t*)&hdr->defsize);
    amx_Align32((uint32_t*)&hdr->cod);
    amx_Align32((uint32_t*)&hdr->dat);
    amx_Align32((uint32_t*)&hdr->hea);
    amx_Align32((uint32_t*)&hdr->stp);
    amx_Align32((uint32_t*)&hdr->cip);
    amx_Align32((uint32_t*)&hdr->publics);
    amx_Align32((uint32_t*)&hdr->natives);
    amx_Align32((uint32_t*)&hdr->libraries);
    amx_Align32((uint32_t*)&hdr->pubvars);
    amx_Align32((uint32_t*)&hdr->tags);
  #endif

  if (hdr->magic != AMX_MAGIC)
    return AMX_ERR_FORMAT;
  if (hdr->file_version > CUR_FILE_VERSION || hdr->amx_version < MIN_FILE_VERSION)
    return AMX_ERR_VERSION;
  if (hdr->file_version == 9 && hdr->amx_version == 9)
    return AMX_ERR_VERSION;
  if (hdr->defsize != sizeof(AMX_FUNCSTUB) && hdr->defsize != sizeof(AMX_FUNCSTUBNT))
    return AMX_ERR_FORMAT;
  if (USENAMETABLE(hdr)) {
    uint16_t *namelength;
    amx_Align32((uint32_t*)&hdr->nametable);
    namelength = (uint16_t*)((unsigned char*)program + (unsigned)hdr->nametable);
    amx_Align16(namelength);
    if (*namelength > sNAMEMAX)
      return AMX_ERR_FORMAT;
  }
  if (hdr->stp <= 0)
    return AMX_ERR_FORMAT;
  #if BYTE_ORDER==BIG_ENDIAN
    if ((hdr->flags & AMX_FLAG_COMPACT) == 0) {
      ucell *code = (ucell *)((unsigned char *)program + (uintptr_t)hdr->cod);
      while (code < (ucell *)((unsigned char *)program + (uintptr_t)hdr->hea))
        swapcell(code++);
    }
  #endif
  if ((hdr->flags & AMX_FLAG_COMPACT) != 0) {
    #if AMX_COMPACTMARGIN > 2
      expand((unsigned char *)program + (uintptr_t)hdr->cod,
             hdr->size - hdr->cod, hdr->hea - hdr->cod);
    #else
      return AMX_ERR_FORMAT;
    #endif
  }

  amx->base = (unsigned char *)program;
  amx->hlw = hdr->hea - hdr->dat;
  amx->stp = hdr->stp - hdr->dat - sizeof(cell);
  amx->hea = amx->hlw;
  amx->stk = amx->stp;
  if (amx->callback == NULL)
    amx->callback = amx_Callback;

  if (amx->data != NULL) {
    data = amx->data;
    memcpy(data, amx->base + (uintptr_t)hdr->dat, (size_t)(hdr->hea - hdr->dat));
  } else {
    data = amx->base + (uintptr_t)hdr->dat;
  }

  *(cell *)(data + (uintptr_t)(hdr->stp - hdr->dat - sizeof(cell))) = 0;

  #ifdef AMX_WIDE_POINTERS
  {
    /* On 64-bit, each 8-byte AMX_FUNCSTUBNT entry in hdr->natives holds a full
     * 64-bit AMX_NATIVE pointer (while native names are walked sequentially
     * from hdr->nametable). Zero all native stubs so the on-disk 32-bit nameofs
     * in bytes 4..7 is not misinterpreted as a non-null 64-bit function address. */
    int numnatives = (int)NUMENTRIES(hdr, natives, libraries);
    AMX_FUNCPART *func = GETENTRY(hdr, natives, 0);
    int i;
    for (i = 0; i < numnatives; i++) {
      ((AMX_FUNCWIDE *)func)->address = 0;
      func = (AMX_FUNCPART *)((unsigned char *)func + hdr->defsize);
    }
  }
  #endif

  if ((err = amx_BrowseRelocate(amx)) != AMX_ERR_NONE)
    return err;

  return AMX_ERR_NONE;
}

int AMXAPI amx_InitJIT(AMX *amx, void *compiled_program, void *reloc_table)
{
  (void)amx;
  (void)compiled_program;
  (void)reloc_table;
  return AMX_ERR_INIT_JIT;
}

int AMXAPI amx_Cleanup(AMX *amx)
{
  (void)amx;
  return AMX_ERR_NONE;
}

int AMXAPI amx_Clone(AMX *amxClone, AMX *amxSource, void *data)
{
  AMX_HEADER *hdr;
  unsigned char _FAR *dataSource;

  if (amxSource == NULL)
    return AMX_ERR_FORMAT;
  if (amxClone == NULL)
    return AMX_ERR_PARAMS;
  if ((amxSource->flags & AMX_FLAG_RELOC) == 0)
    return AMX_ERR_INIT;
  hdr = (AMX_HEADER *)amxSource->base;
  if (hdr->magic != AMX_MAGIC)
    return AMX_ERR_FORMAT;
  if (hdr->file_version > CUR_FILE_VERSION || hdr->amx_version < MIN_FILE_VERSION)
    return AMX_ERR_VERSION;
  if (hdr->file_version == 9 && hdr->amx_version == 9)
    return AMX_ERR_VERSION;

  amxClone->base = amxSource->base;
  amxClone->hlw = hdr->hea - hdr->dat;
  amxClone->stp = hdr->stp - hdr->dat - sizeof(cell);
  amxClone->hea = amxClone->hlw;
  amxClone->stk = amxClone->stp;
  if (amxClone->callback == NULL)
    amxClone->callback = amxSource->callback;
  if (amxClone->debug == NULL)
    amxClone->debug = amxSource->debug;
  amxClone->flags = amxSource->flags;
  amxClone->sysreq_d = amxSource->sysreq_d;

  assert(data != NULL);
  amxClone->data = (unsigned char _FAR *)data;
  dataSource = (amxSource->data != NULL) ? amxSource->data : amxSource->base + (uintptr_t)hdr->dat;
  memcpy(amxClone->data, dataSource, (size_t)(hdr->hea - hdr->dat));
  *(cell *)(amxClone->data + (uintptr_t)amxClone->stp) = 0;

  return AMX_ERR_NONE;
}

int AMXAPI amx_MemInfo(AMX *amx, long *codesize, long *datasize, long *stackheap)
{
  AMX_HEADER *hdr;

  if (amx == NULL)
    return AMX_ERR_FORMAT;
  hdr = (AMX_HEADER *)amx->base;
  if (hdr->magic != AMX_MAGIC)
    return AMX_ERR_FORMAT;
  if (hdr->file_version > CUR_FILE_VERSION || hdr->amx_version < MIN_FILE_VERSION)
    return AMX_ERR_VERSION;
  if (hdr->file_version == 9 && hdr->amx_version == 9)
    return AMX_ERR_VERSION;

  if (codesize != NULL)
    *codesize = hdr->dat - hdr->cod;
  if (datasize != NULL)
    *datasize = hdr->hea - hdr->dat;
  if (stackheap != NULL)
    *stackheap = hdr->stp - hdr->hea;

  return AMX_ERR_NONE;
}

int AMXAPI amx_NameLength(AMX *amx, int *length)
{
  AMX_HEADER *hdr = (AMX_HEADER *)amx->base;
  assert(hdr != NULL);
  assert(hdr->magic == AMX_MAGIC);
  if (USENAMETABLE(hdr)) {
    uint16_t *namelength = (uint16_t*)(amx->base + (unsigned)hdr->nametable);
    *length = *namelength;
  } else {
    *length = hdr->defsize - sizeof(ucell);
  }
  return AMX_ERR_NONE;
}

int AMXAPI amx_NumNatives(AMX *amx, int *number)
{
  AMX_HEADER *hdr = (AMX_HEADER *)amx->base;
  assert(hdr != NULL);
  assert(hdr->magic == AMX_MAGIC);
  assert(hdr->natives <= hdr->libraries);
  *number = NUMENTRIES(hdr, natives, libraries);
  return AMX_ERR_NONE;
}

static const char *get_native_name_safe(const AMX_HEADER *hdr, int index)
{
  int entries = (int)NUMENTRIES(hdr, natives, libraries);
  if (index < 0 || index >= entries)
    return NULL;
  #ifdef AMX_WIDE_POINTERS
    /* On 64-bit, native function pointers overwrite nameofs, so walk nametable sequentially */
    if (USENAMETABLE(hdr)) {
      int numpublics = (int)NUMENTRIES(hdr, publics, natives);
      const char *curname;
      int idx;
      if (numpublics > 0) {
        curname = GETENTRYNAME(hdr, GETENTRY(hdr, publics, numpublics - 1));
        curname = curname + strlen(curname) + 1;
      } else {
        curname = (const char *)hdr + (unsigned)hdr->nametable + sizeof(uint16_t);
      }
      for (idx = 0; idx < index; ++idx)
        curname = curname + strlen(curname) + 1;
      return curname;
    }
    return NULL;
  #else
    return GETENTRYNAME(hdr, GETENTRY(hdr, natives, index));
  #endif
}

int AMXAPI amx_GetNative(AMX *amx, int index, char *funcname)
{
  const AMX_HEADER *hdr = (const AMX_HEADER *)amx->base;
  const char *name;
  assert(hdr != NULL);
  assert(hdr->magic == AMX_MAGIC);
  name = get_native_name_safe(hdr, index);
  if (name == NULL)
    return AMX_ERR_INDEX;
  if (funcname != NULL)
    strcpy(funcname, name);
  return AMX_ERR_NONE;
}

int AMXAPI amx_GetNativeByIndex(const AMX *amx, int index, AMX_NATIVE_INFO *ret)
{
  const AMX_HEADER *hdr;
  const AMX_FUNCPART *func;
  const char *name;
  if (amx == NULL || ret == NULL)
    return AMX_ERR_PARAMS;
  hdr = (const AMX_HEADER *)amx->base;
  name = get_native_name_safe(hdr, index);
  if (name == NULL)
    return AMX_ERR_INDEX;
  func = GETENTRY(hdr, natives, index);
  ret->name = name;
  ret->func = (AMX_NATIVE)((const AMX_FUNCWIDE *)func)->address;
  return AMX_ERR_NONE;
}

int AMXAPI amx_FindNative(AMX *amx, const char *name, int *index)
{
  AMX_HEADER *hdr = (AMX_HEADER *)amx->base;
  int entries = (int)NUMENTRIES(hdr, natives, libraries);

  if (entries > 0) {
    int idx;
    #ifdef AMX_WIDE_POINTERS
      int numpublics = (int)NUMENTRIES(hdr, publics, natives);
      const char *curname;
      if (numpublics > 0) {
        curname = GETENTRYNAME(hdr, GETENTRY(hdr, publics, numpublics - 1));
        curname = curname + strlen(curname) + 1;
      } else if (USENAMETABLE(hdr)) {
        curname = (const char *)hdr + (unsigned)hdr->nametable + sizeof(uint16_t);
      } else {
        *index = INT_MAX;
        return AMX_ERR_VERSION;
      }
      for (idx = 0; idx < entries; ++idx) {
        if (strcmp(name, curname) == 0) {
          *index = idx;
          return AMX_ERR_NONE;
        }
        curname = curname + strlen(curname) + 1;
      }
    #else
      for (idx = 0; idx < entries; ++idx) {
        AMX_FUNCPART *func = GETENTRY(hdr, natives, idx);
        if (strcmp(name, GETENTRYNAME(hdr, func)) == 0) {
          *index = idx;
          return AMX_ERR_NONE;
        }
      }
    #endif
  }

  *index = INT_MAX;
  return AMX_ERR_NOTFOUND;
}

int AMXAPI amx_NumPublics(AMX *amx, int *number)
{
  AMX_HEADER *hdr = (AMX_HEADER *)amx->base;
  assert(hdr != NULL);
  assert(hdr->magic == AMX_MAGIC);
  assert(hdr->publics <= hdr->natives);
  *number = NUMENTRIES(hdr, publics, natives);
  return AMX_ERR_NONE;
}

int AMXAPI amx_GetPublic(AMX *amx, int index, char *funcname)
{
  AMX_HEADER *hdr = (AMX_HEADER *)amx->base;
  AMX_FUNCPART *func;
  assert(hdr != NULL);
  assert(hdr->magic == AMX_MAGIC);
  if (index < 0 || index >= (cell)NUMENTRIES(hdr, publics, natives))
    return AMX_ERR_INDEX;

  func = GETENTRY(hdr, publics, index);
  if (funcname != NULL)
    strcpy(funcname, GETENTRYNAME(hdr, func));
  return AMX_ERR_NONE;
}

int AMXAPI amx_FindPublic(AMX *amx, const char *name, int *index)
{
  int first, last, mid, result;
  char pname[sNAMEMAX + 1];

  amx_NumPublics(amx, &last);
  last--;
  first = 0;
  while (first <= last) {
    mid = (first + last) / 2;
    amx_GetPublic(amx, mid, pname);
    result = strcmp(pname, name);
    if (result > 0) {
      last = mid - 1;
    } else if (result < 0) {
      first = mid + 1;
    } else {
      *index = mid;
      return AMX_ERR_NONE;
    }
  }
  *index = INT_MAX;
  return AMX_ERR_NOTFOUND;
}

int AMXAPI amx_NumPubVars(AMX *amx, int *number)
{
  AMX_HEADER *hdr = (AMX_HEADER *)amx->base;
  assert(hdr != NULL);
  assert(hdr->magic == AMX_MAGIC);
  assert(hdr->pubvars <= hdr->tags);
  *number = NUMENTRIES(hdr, pubvars, tags);
  return AMX_ERR_NONE;
}

int AMXAPI amx_GetPubVar(AMX *amx, int index, char *varname, cell *amx_addr)
{
  AMX_HEADER *hdr = (AMX_HEADER *)amx->base;
  AMX_FUNCPART *var;
  assert(hdr != NULL);
  assert(hdr->magic == AMX_MAGIC);
  if (index < 0 || index >= (cell)NUMENTRIES(hdr, pubvars, tags))
    return AMX_ERR_INDEX;

  var = GETENTRY(hdr, pubvars, index);
  if (varname != NULL)
    strcpy(varname, GETENTRYNAME(hdr, var));
  if (amx_addr != NULL)
    *amx_addr = (cell)var->address;
  return AMX_ERR_NONE;
}

int AMXAPI amx_FindPubVar(AMX *amx, const char *varname, cell *amx_addr)
{
  int first, last, mid, result;
  char pname[sNAMEMAX + 1];
  cell paddr = 0;

  amx_NumPubVars(amx, &last);
  last--;
  first = 0;
  while (first <= last) {
    mid = (first + last) / 2;
    amx_GetPubVar(amx, mid, pname, &paddr);
    result = strcmp(pname, varname);
    if (result > 0) {
      last = mid - 1;
    } else if (result < 0) {
      first = mid + 1;
    } else {
      *amx_addr = paddr;
      return AMX_ERR_NONE;
    }
  }
  *amx_addr = 0;
  return AMX_ERR_NOTFOUND;
}

int AMXAPI amx_NumTags(AMX *amx, int *number)
{
  AMX_HEADER *hdr = (AMX_HEADER *)amx->base;
  assert(hdr != NULL);
  assert(hdr->magic == AMX_MAGIC);
  if (hdr->file_version < 5) {
    *number = 0;
    return AMX_ERR_VERSION;
  }
  if (hdr->file_version < 7) {
    *number = NUMENTRIES(hdr, tags, cod);
  } else {
    *number = NUMENTRIES(hdr, tags, nametable);
  }
  return AMX_ERR_NONE;
}

int AMXAPI amx_GetTag(AMX *amx, int index, char *tagname, cell *tag_id)
{
  AMX_HEADER *hdr = (AMX_HEADER *)amx->base;
  AMX_FUNCPART *tag;
  assert(hdr != NULL);
  assert(hdr->magic == AMX_MAGIC);
  if (hdr->file_version < 5) {
    if (tagname != NULL) *tagname = '\0';
    if (tag_id != NULL) *tag_id = 0;
    return AMX_ERR_VERSION;
  }
  if (hdr->file_version < 7) {
    if (index < 0 || index >= (cell)NUMENTRIES(hdr, tags, cod))
      return AMX_ERR_INDEX;
  } else {
    if (index < 0 || index >= (cell)NUMENTRIES(hdr, tags, nametable))
      return AMX_ERR_INDEX;
  }

  tag = GETENTRY(hdr, tags, index);
  if (tagname != NULL)
    strcpy(tagname, GETENTRYNAME(hdr, tag));
  if (tag_id != NULL)
    *tag_id = (cell)tag->address;
  return AMX_ERR_NONE;
}

int AMXAPI amx_FindTagId(AMX *amx, cell tag_id, char *tagname)
{
  int first, last, mid;
  cell mid_id;

  amx_NumTags(amx, &last);
  last--;
  first = 0;
  while (first <= last) {
    mid = (first + last) / 2;
    amx_GetTag(amx, mid, tagname, &mid_id);
    if (mid_id > tag_id)
      last = mid - 1;
    else if (mid_id < tag_id)
      first = mid + 1;
    else
      return AMX_ERR_NONE;
  }
  if (tagname != NULL)
    *tagname = '\0';
  return AMX_ERR_NOTFOUND;
}

int AMXAPI amx_GetUserData(AMX *amx, long tag, void **ptr)
{
  int index;
  assert(amx != NULL);
  assert(tag != 0);
  for (index = 0; index < AMX_USERNUM && amx->usertags[index] != tag; index++)
    /* nothing */;
  if (index >= AMX_USERNUM)
    return AMX_ERR_USERDATA;
  *ptr = amx->userdata[index];
  return AMX_ERR_NONE;
}

int AMXAPI amx_SetUserData(AMX *amx, long tag, void *ptr)
{
  int index;
  assert(amx != NULL);
  assert(tag != 0);
  for (index = 0; index < AMX_USERNUM && amx->usertags[index] != tag; index++)
    /* nothing */;
  if (index >= AMX_USERNUM)
    for (index = 0; index < AMX_USERNUM && amx->usertags[index] != 0; index++)
      /* nothing */;
  if (index >= AMX_USERNUM)
    return AMX_ERR_USERDATA;
  amx->usertags[index] = tag;
  amx->userdata[index] = ptr;
  return AMX_ERR_NONE;
}

static AMX_NATIVE findfunction(const char *name, const AMX_NATIVE_INFO *list, int number)
{
  int i;
  assert(list != NULL);
  for (i = 0; (i < number || number == -1) && list[i].name != NULL; i++)
    if (strcmp(name, list[i].name) == 0)
      return list[i].func;
  return NULL;
}

int AMXAPI amx_Register(AMX *amx, const AMX_NATIVE_INFO *list, int number)
{
  AMX_FUNCPART *func;
  AMX_HEADER *hdr;
  int i, numnatives, err;
  AMX_NATIVE funcptr;
  #ifdef AMX_WIDE_POINTERS
    const char *curname = NULL;
  #endif

  hdr = (AMX_HEADER *)amx->base;
  assert(hdr != NULL);
  assert(hdr->magic == AMX_MAGIC);
  assert(hdr->natives <= hdr->libraries);
  numnatives = (int)NUMENTRIES(hdr, natives, libraries);

  #ifdef AMX_WIDE_POINTERS
    if (numnatives > 0 && USENAMETABLE(hdr)) {
      int numpublics = (int)NUMENTRIES(hdr, publics, natives);
      if (numpublics > 0) {
        curname = GETENTRYNAME(hdr, GETENTRY(hdr, publics, numpublics - 1));
        curname = curname + strlen(curname) + 1;
      } else {
        curname = (const char *)hdr + (unsigned)hdr->nametable + sizeof(uint16_t);
      }
    }
  #endif

  err = AMX_ERR_NONE;
  func = GETENTRY(hdr, natives, 0);
  for (i = 0; i < numnatives; i++) {
    #ifdef AMX_WIDE_POINTERS
      if (((AMX_FUNCWIDE *)func)->address == 0) {
        funcptr = (list != NULL && curname != NULL) ? findfunction(curname, list, number) : NULL;
        if (funcptr != NULL)
          ((AMX_FUNCWIDE *)func)->address = (uintptr_t)funcptr;
        else
          err = AMX_ERR_NOTFOUND;
      }
      if (curname != NULL)
        curname = curname + strlen(curname) + 1;
    #else
      if (func->address == 0) {
        funcptr = (list != NULL) ? findfunction(GETENTRYNAME(hdr, func), list, number) : NULL;
        if (funcptr != NULL)
          ((AMX_FUNCWIDE *)func)->address = (uintptr_t)funcptr;
        else
          err = AMX_ERR_NOTFOUND;
      }
    #endif
    func = (AMX_FUNCPART *)((unsigned char *)func + hdr->defsize);
  }
  if (err == AMX_ERR_NONE)
    amx->flags |= AMX_FLAG_NTVREG;
  return err;
}

AMX_NATIVE_INFO * AMXAPI amx_NativeInfo(const char *name, AMX_NATIVE func)
{
  static AMX_NATIVE_INFO n;
  n.name = name;
  n.func = func;
  return &n;
}

int AMXAPI amx_Push(AMX *amx, cell value)
{
  AMX_HEADER *hdr;
  unsigned char *data;

  if (amx->hea + STKMARGIN > amx->stk)
    return AMX_ERR_STACKERR;
  hdr = (AMX_HEADER *)amx->base;
  data = (amx->data != NULL) ? amx->data : amx->base + (uintptr_t)hdr->dat;
  amx->stk -= sizeof(cell);
  amx->paramcount += 1;
  *(cell *)(data + (uintptr_t)amx->stk) = value;
  return AMX_ERR_NONE;
}

int AMXAPI amx_PushArray(AMX *amx, cell *amx_addr, cell **phys_addr, const cell array[], int numcells)
{
  cell *paddr, xaddr;
  int err;

  assert(amx != NULL);
  assert(array != NULL);

  err = amx_Allot(amx, numcells, &xaddr, &paddr);
  if (err == AMX_ERR_NONE) {
    if (amx_addr != NULL)
      *amx_addr = xaddr;
    if (phys_addr != NULL)
      *phys_addr = paddr;
    memcpy(paddr, array, (size_t)numcells * sizeof(cell));
    err = amx_Push(amx, xaddr);
  }
  return err;
}

int AMXAPI amx_PushStringLen(AMX *amx, cell *amx_addr, cell **phys_addr, const char *string, int length, int pack, int use_wchar)
{
  cell *paddr, xaddr;
  int numcells, err;

  assert(amx != NULL);
  numcells = length + 1;
  if (pack)
    numcells = (numcells + (int)sizeof(cell) - 1) / (int)sizeof(cell);
  err = amx_Allot(amx, numcells, &xaddr, &paddr);
  if (err == AMX_ERR_NONE) {
    if (amx_addr != NULL)
      *amx_addr = xaddr;
    if (phys_addr != NULL)
      *phys_addr = paddr;
    amx_SetStringLen(paddr, string, length, pack, use_wchar, UNLIMITED);
    err = amx_Push(amx, xaddr);
  }
  return err;
}

int AMXAPI amx_PushString(AMX *amx, cell *amx_addr, cell **phys_addr, const char *string, int pack, int use_wchar)
{
  size_t length;
  assert(string != NULL);
  length = use_wchar ? wcslen((const wchar_t *)string) : strlen(string);
  return amx_PushStringLen(amx, amx_addr, phys_addr, string, (int)length, pack, use_wchar);
}

int AMXAPI amx_SetDefaultExtHooks(AMX_EXT_HOOKS *ext_hooks)
{
  g_default_ext_hooks = ext_hooks;
  return AMX_ERR_NONE;
}

int AMXAPI amx_GetExtHooks(AMX *amx, AMX_EXT_HOOKS **ext_hooks)
{
  void *ptr = NULL;
  assert(amx != NULL);
  assert(ext_hooks != NULL);
  if (amx_GetUserData(amx, AMX_USERTAG('c', 'd', 'e', 'h'), &ptr) == AMX_ERR_NONE && ptr != NULL) {
    *ext_hooks = (AMX_EXT_HOOKS *)ptr;
    return AMX_ERR_NONE;
  }
  if (g_default_ext_hooks != NULL) {
    *ext_hooks = g_default_ext_hooks;
    return AMX_ERR_NONE;
  }
  *ext_hooks = NULL;
  return AMX_ERR_USERDATA;
}

int AMXAPI amx_SetExtHooks(AMX *amx, AMX_EXT_HOOKS *ext_hooks)
{
  assert(ext_hooks != NULL);
  g_default_ext_hooks = ext_hooks;
  if (amx != NULL) {
    /* Best-effort per-AMX registration; if all 4 userdata slots are full, g_default_ext_hooks still serves it */
    amx_SetUserData(amx, AMX_USERTAG('c', 'd', 'e', 'h'), ext_hooks);
  }
  return AMX_ERR_NONE;
}

int AMXAPI amx_RaiseExecError(AMX *amx, cell index, cell *retval, int error)
{
  AMX_EXT_HOOKS *ext_hooks = NULL;
  assert(amx != NULL);
  if (amx_GetExtHooks(amx, &ext_hooks) != AMX_ERR_NONE || ext_hooks == NULL)
    return AMX_ERR_NOTFOUND;
  if (ext_hooks->exec_error == NULL)
    return AMX_ERR_NOTFOUND;
  ext_hooks->exec_error(amx, index, retval, error);
  return AMX_ERR_NONE;
}

#define _R(base, addr)         (* (cell *)((unsigned char*)(base) + (uintptr_t)(uint32_t)(addr)))
#define _R8(base, addr)        (* (unsigned char *)((unsigned char*)(base) + (uintptr_t)(uint32_t)(addr)))
#define _R16(base, addr)       (* (uint16_t *)((unsigned char*)(base) + (uintptr_t)(uint32_t)(addr)))
#define _R32(base, addr)       (* (uint32_t *)((unsigned char*)(base) + (uintptr_t)(uint32_t)(addr)))
#define _W(base, addr, value)   ((*(cell *)((unsigned char*)(base) + (uintptr_t)(uint32_t)(addr))) = (cell)(value))
#define _W8(base, addr, value)  ((*(unsigned char *)((unsigned char*)(base) + (uintptr_t)(uint32_t)(addr))) = (unsigned char)(value))
#define _W16(base, addr, value) ((*(uint16_t *)((unsigned char*)(base) + (uintptr_t)(uint32_t)(addr))) = (uint16_t)(value))
#define _W32(base, addr, value) ((*(uint32_t *)((unsigned char*)(base) + (uintptr_t)(uint32_t)(addr))) = (uint32_t)(value))

#if -8/3==-2 && 8/-3==-2
  #define TRUNC_SDIV
#else
  #define IABS(a)       ((a) >= 0 ? (a) : (-a))
#endif

#define GETPARAM(v)     ( (v) = *(cell *)cip++ )
#define SKIPPARAM(n)    ( cip = (cell *)cip + (n) )
#define PUSH(v)         ( stk -= sizeof(cell), _W(data, stk, (v)) )
#define POP(v)          ( (v) = _R(data, stk), stk += sizeof(cell) )

#define ABORT(amx, v)   do {                                         \
                          int _err = (int)(v);                       \
                          CD_SAVE_WATERMARKS();                      \
                          (amx)->pri = pri;                          \
                          (amx)->alt = alt;                          \
                          (amx)->stk = stk;                          \
                          (amx)->hea = hea;                          \
                          (amx)->frm = frm;                          \
                          amx_RaiseExecError((amx), index, retval, _err); \
                          (amx)->stk = reset_stk;                    \
                          (amx)->hea = reset_hea;                    \
                          return _err;                               \
                        } while (0)

#define CHKNAUGHT()     do { if (address_naught_ctl != NULL && address_naught_ctl(amx, -1) != 0) { amx->cip = (cell)((unsigned char *)cip - code); ABORT(amx, AMX_ERR_ADDRESS_0); } } while (0)
#define CHKMARGIN()     do { if (hea + STKMARGIN > stk) { amx->cip = (cell)((unsigned char *)cip - code); ABORT(amx, AMX_ERR_STACKERR); } } while (0)
#define CHKSTACK()      do { if (stk > amx->stp) { amx->cip = (cell)((unsigned char *)cip - code); ABORT(amx, AMX_ERR_STACKLOW); } } while (0)
#define CHKHEAP()       do { if (hea < amx->hlw) { amx->cip = (cell)((unsigned char *)cip - code); ABORT(amx, AMX_ERR_HEAPLOW); } } while (0)
#define CHKMEMBLOCK(addr, sz) \
  do { \
    if ((sz) < 0 || (addr) < 0 || (ucell)(sz) > (ucell)amx->stp || \
        (ucell)(addr) > (ucell)amx->stp - (ucell)(sz) || \
        ((sz) > 0 && hea < stk && (addr) < stk && ((addr) + (sz)) > hea)) { \
      amx->cip = (cell)((unsigned char *)cip - code); \
      ABORT(amx, AMX_ERR_MEMACCESS); \
    } \
  } while (0)
#define CD_SHIFT_MASK   ((ucell)(8 * sizeof(cell) - 1))

static int amx_Exec_Switch(AMX *amx, cell *retval, int index);

#if (defined __GNUC__ && !defined __MINGW32__) && !defined __64BIT__

/* Fast GNU C 32-bit computed-goto interpreter supporting BOTH v8 (SYSREQ.D) and v9 (SYSREQ.N + macro ops) */
#define NEXT(cip)       do { (amx)->cip = (cell)((unsigned char *)(cip) - code); goto **(void **)(cip)++; } while (0)

int AMXAPI amx_Exec(AMX *amx, cell *retval, int index)
{
  static const void * const amx_opcodelist_v8[] = {
        &&op_none,      &&op_load_pri,  &&op_load_alt,  &&op_load_s_pri,
        &&op_load_s_alt,&&op_lref_pri,  &&op_lref_alt,  &&op_lref_s_pri,
        &&op_lref_s_alt,&&op_load_i,    &&op_lodb_i,    &&op_const_pri,
        &&op_const_alt, &&op_addr_pri,  &&op_addr_alt,  &&op_stor_pri,
        &&op_stor_alt,  &&op_stor_s_pri,&&op_stor_s_alt,&&op_sref_pri,
        &&op_sref_alt,  &&op_sref_s_pri,&&op_sref_s_alt,&&op_stor_i,
        &&op_strb_i,    &&op_lidx,      &&op_lidx_b,    &&op_idxaddr,
        &&op_idxaddr_b, &&op_align_pri, &&op_align_alt, &&op_lctrl,
        &&op_sctrl,     &&op_move_pri,  &&op_move_alt,  &&op_xchg,
        &&op_push_pri,  &&op_push_alt,  &&op_push_r,    &&op_push_c,
        &&op_push,      &&op_push_s,    &&op_pop_pri,   &&op_pop_alt,
        &&op_stack,     &&op_heap,      &&op_proc,      &&op_ret,
        &&op_retn,      &&op_call,      &&op_call_pri,  &&op_jump,
        &&op_jrel,      &&op_jzer,      &&op_jnz,       &&op_jeq,
        &&op_jneq,      &&op_jless,     &&op_jleq,      &&op_jgrtr,
        &&op_jgeq,      &&op_jsless,    &&op_jsleq,     &&op_jsgrtr,
        &&op_jsgeq,     &&op_shl,       &&op_shr,       &&op_sshr,
        &&op_shl_c_pri, &&op_shl_c_alt, &&op_shr_c_pri, &&op_shr_c_alt,
        &&op_smul,      &&op_sdiv,      &&op_sdiv_alt,  &&op_umul,
        &&op_udiv,      &&op_udiv_alt,  &&op_add,       &&op_sub,
        &&op_sub_alt,   &&op_and,       &&op_or,        &&op_xor,
        &&op_not,       &&op_neg,       &&op_invert,    &&op_add_c,
        &&op_smul_c,    &&op_zero_pri,  &&op_zero_alt,  &&op_zero,
        &&op_zero_s,    &&op_sign_pri,  &&op_sign_alt,  &&op_eq,
        &&op_neq,       &&op_less,      &&op_leq,       &&op_grtr,
        &&op_geq,       &&op_sless,     &&op_sleq,      &&op_sgrtr,
        &&op_sgeq,      &&op_eq_c_pri,  &&op_eq_c_alt,  &&op_inc_pri,
        &&op_inc_alt,   &&op_inc,       &&op_inc_s,     &&op_inc_i,
        &&op_dec_pri,   &&op_dec_alt,   &&op_dec,       &&op_dec_s,
        &&op_dec_i,     &&op_movs,      &&op_cmps,      &&op_fill,
        &&op_halt,      &&op_bounds,    &&op_sysreq_pri,&&op_sysreq_c,
        &&op_file,      &&op_line,      &&op_symbol,    &&op_srange,
        &&op_jump_pri,  &&op_switch,    &&op_casetbl,   &&op_swap_pri,
        &&op_swap_alt,  &&op_push_adr,  &&op_nop,       &&op_sysreq_d,
        &&op_symtag,    &&op_break,     &&op_push2_c,   &&op_push2,
        &&op_push2_s,   &&op_push2_adr, &&op_push3_c,   &&op_push3,
        &&op_push3_s,   &&op_push3_adr, &&op_push4_c,   &&op_push4,
        &&op_push4_s,   &&op_push4_adr, &&op_push5_c,   &&op_push5,
        &&op_push5_s,   &&op_push5_adr, &&op_load_both, &&op_load_s_both,
        &&op_const,     &&op_const_s,   &&op_sysreq_d,  &&op_sysreq_nd };

  static const void * const amx_opcodelist_v9[] = {
        &&op_none,      &&op_load_pri,  &&op_load_alt,  &&op_load_s_pri,
        &&op_load_s_alt,&&op_lref_pri,  &&op_lref_alt,  &&op_lref_s_pri,
        &&op_lref_s_alt,&&op_load_i,    &&op_lodb_i,    &&op_const_pri,
        &&op_const_alt, &&op_addr_pri,  &&op_addr_alt,  &&op_stor_pri,
        &&op_stor_alt,  &&op_stor_s_pri,&&op_stor_s_alt,&&op_sref_pri,
        &&op_sref_alt,  &&op_sref_s_pri,&&op_sref_s_alt,&&op_stor_i,
        &&op_strb_i,    &&op_lidx,      &&op_lidx_b,    &&op_idxaddr,
        &&op_idxaddr_b, &&op_align_pri, &&op_align_alt, &&op_lctrl,
        &&op_sctrl,     &&op_move_pri,  &&op_move_alt,  &&op_xchg,
        &&op_push_pri,  &&op_push_alt,  &&op_push_r,    &&op_push_c,
        &&op_push,      &&op_push_s,    &&op_pop_pri,   &&op_pop_alt,
        &&op_stack,     &&op_heap,      &&op_proc,      &&op_ret,
        &&op_retn,      &&op_call,      &&op_call_pri,  &&op_jump,
        &&op_jrel,      &&op_jzer,      &&op_jnz,       &&op_jeq,
        &&op_jneq,      &&op_jless,     &&op_jleq,      &&op_jgrtr,
        &&op_jgeq,      &&op_jsless,    &&op_jsleq,     &&op_jsgrtr,
        &&op_jsgeq,     &&op_shl,       &&op_shr,       &&op_sshr,
        &&op_shl_c_pri, &&op_shl_c_alt, &&op_shr_c_pri, &&op_shr_c_alt,
        &&op_smul,      &&op_sdiv,      &&op_sdiv_alt,  &&op_umul,
        &&op_udiv,      &&op_udiv_alt,  &&op_add,       &&op_sub,
        &&op_sub_alt,   &&op_and,       &&op_or,        &&op_xor,
        &&op_not,       &&op_neg,       &&op_invert,    &&op_add_c,
        &&op_smul_c,    &&op_zero_pri,  &&op_zero_alt,  &&op_zero,
        &&op_zero_s,    &&op_sign_pri,  &&op_sign_alt,  &&op_eq,
        &&op_neq,       &&op_less,      &&op_leq,       &&op_grtr,
        &&op_geq,       &&op_sless,     &&op_sleq,      &&op_sgrtr,
        &&op_sgeq,      &&op_eq_c_pri,  &&op_eq_c_alt,  &&op_inc_pri,
        &&op_inc_alt,   &&op_inc,       &&op_inc_s,     &&op_inc_i,
        &&op_dec_pri,   &&op_dec_alt,   &&op_dec,       &&op_dec_s,
        &&op_dec_i,     &&op_movs,      &&op_cmps,      &&op_fill,
        &&op_halt,      &&op_bounds,    &&op_sysreq_pri,&&op_sysreq_c,
        &&op_file,      &&op_line,      &&op_symbol,    &&op_srange,
        &&op_jump_pri,  &&op_switch,    &&op_casetbl,   &&op_swap_pri,
        &&op_swap_alt,  &&op_push_adr,  &&op_nop,       &&op_sysreq_n,
        &&op_symtag,    &&op_break,     &&op_push2_c,   &&op_push2,
        &&op_push2_s,   &&op_push2_adr, &&op_push3_c,   &&op_push3,
        &&op_push3_s,   &&op_push3_adr, &&op_push4_c,   &&op_push4,
        &&op_push4_s,   &&op_push4_adr, &&op_push5_c,   &&op_push5,
        &&op_push5_s,   &&op_push5_adr, &&op_load_both, &&op_load_s_both,
        &&op_const,     &&op_const_s,   &&op_sysreq_d,  &&op_sysreq_nd };

  AMX_HEADER *hdr;
  AMX_FUNCPART *func;
  unsigned char *code, *data;
  cell pri, alt, stk, frm, hea;
  cell reset_stk, reset_hea, *cip;
  cell offs, val;
  ucell codesize;
  int num, i;
  AMX_EXT_HOOKS *ext_hooks = NULL;
  AMX_LCT_CTL long_call_ctl = NULL;
  AMX_ADDR_0_CTL address_naught_ctl = NULL;

  assert(amx != NULL);
  if ((amx->flags & AMX_FLAG_BROWSE) == AMX_FLAG_BROWSE) {
    assert(sizeof(cell) == sizeof(void *));
    assert(retval != NULL);
    hdr = (AMX_HEADER *)amx->base;
    if (hdr != NULL && hdr->file_version >= 9)
      *retval = (cell)(uintptr_t)amx_opcodelist_v9;
    else
      *retval = (cell)(uintptr_t)amx_opcodelist_v8;
    return 0;
  }

  if (amx->callback == NULL)
    return AMX_ERR_CALLBACK;
  if ((amx->flags & AMX_FLAG_RELOC) == 0)
    return AMX_ERR_INIT;
  if ((amx->flags & AMX_FLAG_NTVREG) == 0) {
    if ((num = amx_Register(amx, NULL, 0)) != AMX_ERR_NONE)
      return num;
  }

  hdr = (AMX_HEADER *)amx->base;
  assert(hdr->magic == AMX_MAGIC);
  codesize = (ucell)(hdr->dat - hdr->cod);
  code = amx->base + (uintptr_t)hdr->cod;
  data = (amx->data != NULL) ? amx->data : amx->base + (uintptr_t)hdr->dat;
  hea = amx->hea;
  stk = amx->stk;
  reset_stk = stk;
  reset_hea = hea;
  alt = frm = pri = 0;
  num = 0;

  if (index == AMX_EXEC_MAIN) {
    if (hdr->cip < 0)
      return AMX_ERR_INDEX;
    cip = (cell *)(code + (uintptr_t)hdr->cip);
  } else if (index == AMX_EXEC_CONT) {
    frm = amx->frm;
    stk = amx->stk;
    hea = amx->hea;
    pri = amx->pri;
    alt = amx->alt;
    reset_stk = amx->reset_stk;
    reset_hea = amx->reset_hea;
    cip = (cell *)(code + (uintptr_t)amx->cip);
  } else if (index < 0) {
    return AMX_ERR_INDEX;
  } else {
    if (index >= (int)NUMENTRIES(hdr, publics, natives))
      return AMX_ERR_INDEX;
    func = GETENTRY(hdr, publics, index);
    cip = (cell *)(code + (uintptr_t)func->address);
  }

  /* If the host loaded this AMX without computed-goto relocation (e.g. open.mp
   * Linux x86 with AMX_FLAG_NO_RELOC or raw integer opcodes), safely dispatch
   * to the ANSI switch interpreter instead of jumping to integer opcode values! */
  if ((amx->flags & AMX_FLAG_NO_RELOC) != 0 || (ucell)*cip < 256u)
    return amx_Exec_Switch(amx, retval, index);

  amx_GetExtHooks(amx, &ext_hooks);
  if (ext_hooks != NULL) {
    long_call_ctl = ext_hooks->long_call_ctl;
    address_naught_ctl = ext_hooks->address_naught_ctl;
  }

  CHKSTACK();
  CHKHEAP();

  if (index != AMX_EXEC_CONT) {
    reset_stk += amx->paramcount * (cell)sizeof(cell);
    PUSH(amx->paramcount * (cell)sizeof(cell));
    amx->paramcount = 0;
    PUSH(0);
    CD_TRACK_STK();
  }
  CHKMARGIN();

  NEXT(cip);

  op_none:
    ABORT(amx, AMX_ERR_INVINSTR);
  op_load_pri:
    GETPARAM(offs);
    pri = _R(data, offs);
    NEXT(cip);
  op_load_alt:
    GETPARAM(offs);
    alt = _R(data, offs);
    NEXT(cip);
  op_load_s_pri:
    GETPARAM(offs);
    pri = _R(data, frm + offs);
    NEXT(cip);
  op_load_s_alt:
    GETPARAM(offs);
    alt = _R(data, frm + offs);
    NEXT(cip);
  op_lref_pri:
    GETPARAM(offs);
    offs = _R(data, offs);
    pri = _R(data, offs);
    NEXT(cip);
  op_lref_alt:
    GETPARAM(offs);
    offs = _R(data, offs);
    alt = _R(data, offs);
    NEXT(cip);
  op_lref_s_pri:
    amx->frm = frm;
    amx->stk = stk;
    GETPARAM(offs);
    offs = _R(data, frm + offs);
    pri = _R(data, offs);
    NEXT(cip);
  op_lref_s_alt:
    amx->frm = frm;
    amx->stk = stk;
    GETPARAM(offs);
    offs = _R(data, frm + offs);
    alt = _R(data, offs);
    NEXT(cip);
  op_load_i:
    if ((pri >= hea && pri < stk) || (ucell)pri >= (ucell)amx->stp)
      ABORT(amx, AMX_ERR_MEMACCESS);
    pri = _R(data, pri);
    NEXT(cip);
  op_lodb_i:
    GETPARAM(offs);
    if ((pri >= hea && pri < stk) || (ucell)pri >= (ucell)amx->stp)
      ABORT(amx, AMX_ERR_MEMACCESS);
    switch ((int)offs) {
    case 1: pri = _R8(data, pri); break;
    case 2: pri = _R16(data, pri); break;
    case 4: pri = (cell)_R32(data, pri); break;
    }
    NEXT(cip);
  op_const_pri:
    GETPARAM(pri);
    NEXT(cip);
  op_const_alt:
    GETPARAM(alt);
    NEXT(cip);
  op_addr_pri:
    GETPARAM(pri);
    pri += frm;
    NEXT(cip);
  op_addr_alt:
    GETPARAM(alt);
    alt += frm;
    NEXT(cip);
  op_stor_pri:
    GETPARAM(offs);
    if ((int)offs == 0) CHKNAUGHT();
    _W(data, offs, pri);
    NEXT(cip);
  op_stor_alt:
    GETPARAM(offs);
    if ((int)offs == 0) CHKNAUGHT();
    _W(data, offs, alt);
    NEXT(cip);
  op_stor_s_pri:
    GETPARAM(offs);
    if ((int)(frm + offs) == 0) CHKNAUGHT();
    _W(data, frm + offs, pri);
    NEXT(cip);
  op_stor_s_alt:
    GETPARAM(offs);
    if ((int)(frm + offs) == 0) CHKNAUGHT();
    _W(data, frm + offs, alt);
    NEXT(cip);
  op_sref_pri:
    amx->frm = frm;
    amx->stk = stk;
    GETPARAM(offs);
    offs = _R(data, offs);
    if ((int)offs == 0) CHKNAUGHT();
    _W(data, offs, pri);
    NEXT(cip);
  op_sref_alt:
    amx->frm = frm;
    amx->stk = stk;
    GETPARAM(offs);
    offs = _R(data, offs);
    if ((int)offs == 0) CHKNAUGHT();
    _W(data, offs, alt);
    NEXT(cip);
  op_sref_s_pri:
    amx->frm = frm;
    amx->stk = stk;
    GETPARAM(offs);
    offs = _R(data, frm + offs);
    if ((int)offs == 0) CHKNAUGHT();
    _W(data, offs, pri);
    NEXT(cip);
  op_sref_s_alt:
    amx->frm = frm;
    amx->stk = stk;
    GETPARAM(offs);
    offs = _R(data, frm + offs);
    if ((int)offs == 0) CHKNAUGHT();
    _W(data, offs, alt);
    NEXT(cip);
  op_stor_i:
    if ((alt >= hea && alt < stk) || (ucell)alt >= (ucell)amx->stp)
      ABORT(amx, AMX_ERR_MEMACCESS);
    if ((int)alt == 0) CHKNAUGHT();
    _W(data, alt, pri);
    NEXT(cip);
  op_strb_i:
    GETPARAM(offs);
    if ((alt >= hea && alt < stk) || (ucell)alt >= (ucell)amx->stp)
      ABORT(amx, AMX_ERR_MEMACCESS);
    if ((int)alt == 0) CHKNAUGHT();
    switch ((int)offs) {
    case 1: _W8(data, alt, pri); break;
    case 2: _W16(data, alt, pri); break;
    case 4: _W32(data, alt, pri); break;
    }
    NEXT(cip);
  op_lidx:
    offs = pri * (cell)sizeof(cell) + alt;
    if ((offs >= hea && offs < stk) || (ucell)offs >= (ucell)amx->stp)
      ABORT(amx, AMX_ERR_MEMACCESS);
    pri = _R(data, offs);
    NEXT(cip);
  op_lidx_b:
    GETPARAM(offs);
    offs = (pri << (int)offs) + alt;
    if ((offs >= hea && offs < stk) || (ucell)offs >= (ucell)amx->stp)
      ABORT(amx, AMX_ERR_MEMACCESS);
    pri = _R(data, offs);
    NEXT(cip);
  op_idxaddr:
    pri = pri * (cell)sizeof(cell) + alt;
    NEXT(cip);
  op_idxaddr_b:
    GETPARAM(offs);
    pri = (pri << (int)offs) + alt;
    NEXT(cip);
  op_align_pri:
    GETPARAM(offs);
    #if BYTE_ORDER==LITTLE_ENDIAN
      if ((size_t)offs < sizeof(cell))
        pri ^= (cell)sizeof(cell) - offs;
    #endif
    NEXT(cip);
  op_align_alt:
    GETPARAM(offs);
    #if BYTE_ORDER==LITTLE_ENDIAN
      if ((size_t)offs < sizeof(cell))
        alt ^= (cell)sizeof(cell) - offs;
    #endif
    NEXT(cip);
  op_lctrl:
    GETPARAM(offs);
    switch (offs) {
    case 0: pri = hdr->cod; break;
    case 1: pri = hdr->dat; break;
    case 2: pri = hea; break;
    case 3: pri = amx->stp; break;
    case 4: pri = stk; break;
    case 5: pri = frm; break;
    case 6: pri = (cell)((unsigned char *)cip - code); break;
    case 0xFE:
      pri = (long_call_ctl != NULL) ? long_call_ctl(amx, AMX_LCT_OPTION, AMX_LCT_OPTION_CURRENT) : 0;
      break;
    case 0xFF:
      if (ext_hooks == NULL)
        pri = 1 | 16 | 32 | 64;
      else
        pri = 1 | 32
            | ((long_call_ctl != NULL ? long_call_ctl(amx, AMX_LCT_OPTION, AMX_LCT_OPTION_ACTIVE) : 0) << 1)
            | 64
            | ((address_naught_ctl != NULL ? address_naught_ctl(amx, -1) : 0) << 7);
      break;
    }
    NEXT(cip);
  op_sctrl:
    GETPARAM(offs);
    switch (offs) {
    case 0:
    case 1:
    case 3:
      break;
    case 2:
      hea = pri;
      CD_TRACK_HEA();
      break;
    case 4:
      stk = pri;
      CD_TRACK_STK();
      break;
    case 5:
      frm = pri;
      break;
    case 6:
      if ((ucell)pri >= codesize)
        ABORT(amx, AMX_ERR_MEMACCESS);
      cip = (cell *)(code + (uintptr_t)pri);
      break;
    case 0xFE:
      if (long_call_ctl != NULL)
        long_call_ctl(amx, AMX_LCT_SET_TIME, pri);
      break;
    case 0xFF:
      if (long_call_ctl != NULL && (pri & 32)) {
        if (pri & 2)
          long_call_ctl(amx, AMX_LCT_OPTION, AMX_LCT_OPTION_ENABLE);
        else if (pri & 4)
          long_call_ctl(amx, AMX_LCT_OPTION, AMX_LCT_OPTION_RESET);
        else if (pri & 8)
          long_call_ctl(amx, AMX_LCT_OPTION, AMX_LCT_OPTION_RESTART);
        else
          long_call_ctl(amx, AMX_LCT_OPTION, AMX_LCT_OPTION_DISABLE);
      }
      if (address_naught_ctl != NULL && (pri & 64)) {
        address_naught_ctl(amx, (pri & 128) ? 1 : 0);
      }
      break;
    }
    NEXT(cip);
  op_move_pri:
    pri = alt;
    NEXT(cip);
  op_move_alt:
    alt = pri;
    NEXT(cip);
  op_xchg:
    offs = pri;
    pri = alt;
    alt = offs;
    NEXT(cip);
  op_push_pri:
    PUSH(pri);
    NEXT(cip);
  op_push_alt:
    PUSH(alt);
    NEXT(cip);
  op_push_c:
    GETPARAM(offs);
    PUSH(offs);
    NEXT(cip);
  op_push_r:
    GETPARAM(offs);
    while (offs--)
      PUSH(pri);
    CD_TRACK_STK();
    NEXT(cip);
  op_push:
    GETPARAM(offs);
    PUSH(_R(data, offs));
    NEXT(cip);
  op_push_s:
    GETPARAM(offs);
    PUSH(_R(data, frm + offs));
    NEXT(cip);
  op_pop_pri:
    POP(pri);
    NEXT(cip);
  op_pop_alt:
    POP(alt);
    NEXT(cip);
  op_stack:
    GETPARAM(offs);
    alt = stk;
    stk += offs;
    CD_TRACK_STK();
    CHKMARGIN();
    CHKSTACK();
    NEXT(cip);
  op_heap:
    GETPARAM(offs);
    alt = hea;
    hea += offs;
    CD_TRACK_HEA();
    CHKMARGIN();
    CHKHEAP();
    NEXT(cip);
  op_proc:
    PUSH(frm);
    frm = stk;
    CD_TRACK_STK();
    CHKMARGIN();
    NEXT(cip);
  op_ret:
    POP(frm);
    POP(offs);
    if ((ucell)offs >= codesize)
      ABORT(amx, AMX_ERR_MEMACCESS);
    cip = (cell *)(code + (uintptr_t)offs);
    NEXT(cip);
  op_retn:
    POP(frm);
    POP(offs);
    if ((ucell)offs >= codesize)
      ABORT(amx, AMX_ERR_MEMACCESS);
    cip = (cell *)(code + (uintptr_t)offs);
    stk += _R(data, stk) + (cell)sizeof(cell);
    amx->stk = stk;
    NEXT(cip);
  op_call:
    PUSH((cell)(((unsigned char *)cip - code) + sizeof(cell)));
    cip = JUMPABS(code, cip);
    CD_WATERMARK();
    CHECK_LCT_CALL(2);
    NEXT(cip);
  op_call_pri:
    if ((ucell)pri >= codesize)
      ABORT(amx, AMX_ERR_MEMACCESS);
    PUSH((cell)((unsigned char *)cip - code));
    cip = (cell *)(code + (uintptr_t)pri);
    CD_WATERMARK();
    CHECK_LCT_CALL(1);
    NEXT(cip);
  op_jump: {
    cell *dest_ = JUMPABS(code, cip);
    CHECK_LCT_JUMP(dest_);
    cip = dest_;
    NEXT(cip);
  }
  op_jrel: {
    offs = *cip;
    cell *dest_ = (cell *)((unsigned char *)cip + (int)offs + sizeof(cell));
    CHECK_LCT_JUMP(dest_);
    cip = dest_;
    NEXT(cip);
  }
  op_jzer:
    CD_COND_JUMP(pri == 0);
    NEXT(cip);
  op_jnz:
    CD_COND_JUMP(pri != 0);
    NEXT(cip);
  op_jeq:
    CD_COND_JUMP(pri == alt);
    NEXT(cip);
  op_jneq:
    CD_COND_JUMP(pri != alt);
    NEXT(cip);
  op_jless:
    CD_COND_JUMP((ucell)pri < (ucell)alt);
    NEXT(cip);
  op_jleq:
    CD_COND_JUMP((ucell)pri <= (ucell)alt);
    NEXT(cip);
  op_jgrtr:
    CD_COND_JUMP((ucell)pri > (ucell)alt);
    NEXT(cip);
  op_jgeq:
    CD_COND_JUMP((ucell)pri >= (ucell)alt);
    NEXT(cip);
  op_jsless:
    CD_COND_JUMP(pri < alt);
    NEXT(cip);
  op_jsleq:
    CD_COND_JUMP(pri <= alt);
    NEXT(cip);
  op_jsgrtr:
    CD_COND_JUMP(pri > alt);
    NEXT(cip);
  op_jsgeq:
    CD_COND_JUMP(pri >= alt);
    NEXT(cip);
  op_shl:
    pri = (cell)((ucell)pri << ((ucell)alt & CD_SHIFT_MASK));
    NEXT(cip);
  op_shr:
    pri = (cell)((ucell)pri >> ((ucell)alt & CD_SHIFT_MASK));
    NEXT(cip);
  op_sshr:
    pri >>= ((ucell)alt & CD_SHIFT_MASK);
    NEXT(cip);
  op_shl_c_pri:
    GETPARAM(offs);
    pri = (cell)((ucell)pri << ((ucell)offs & CD_SHIFT_MASK));
    NEXT(cip);
  op_shl_c_alt:
    GETPARAM(offs);
    alt = (cell)((ucell)alt << ((ucell)offs & CD_SHIFT_MASK));
    NEXT(cip);
  op_shr_c_pri:
    GETPARAM(offs);
    pri = (cell)((ucell)pri >> ((ucell)offs & CD_SHIFT_MASK));
    NEXT(cip);
  op_shr_c_alt:
    GETPARAM(offs);
    alt = (cell)((ucell)alt >> ((ucell)offs & CD_SHIFT_MASK));
    NEXT(cip);
  op_smul:
    pri *= alt;
    NEXT(cip);
  op_sdiv:
    if (alt == 0)
      ABORT(amx, AMX_ERR_DIVIDE);
    if ((ucell)pri == ((ucell)1 << (8 * sizeof(cell) - 1)) && alt == -1)
      ABORT(amx, AMX_ERR_DOMAIN);
    offs = (pri % alt + alt) % alt;
    pri = (pri - offs) / alt;
    alt = offs;
    NEXT(cip);
  op_sdiv_alt:
    if (pri == 0)
      ABORT(amx, AMX_ERR_DIVIDE);
    if ((ucell)alt == ((ucell)1 << (8 * sizeof(cell) - 1)) && pri == -1)
      ABORT(amx, AMX_ERR_DOMAIN);
    offs = (alt % pri + pri) % pri;
    pri = (alt - offs) / pri;
    alt = offs;
    NEXT(cip);
  op_umul:
    pri = (ucell)pri * (ucell)alt;
    NEXT(cip);
  op_udiv:
    if (alt == 0)
      ABORT(amx, AMX_ERR_DIVIDE);
    offs = (ucell)pri % (ucell)alt;
    pri = (ucell)pri / (ucell)alt;
    alt = offs;
    NEXT(cip);
  op_udiv_alt:
    if (pri == 0)
      ABORT(amx, AMX_ERR_DIVIDE);
    offs = (ucell)alt % (ucell)pri;
    pri = (ucell)alt / (ucell)pri;
    alt = offs;
    NEXT(cip);
  op_add:
    pri += alt;
    NEXT(cip);
  op_sub:
    pri -= alt;
    NEXT(cip);
  op_sub_alt:
    pri = alt - pri;
    NEXT(cip);
  op_and:
    pri &= alt;
    NEXT(cip);
  op_or:
    pri |= alt;
    NEXT(cip);
  op_xor:
    pri ^= alt;
    NEXT(cip);
  op_not:
    pri = !pri;
    NEXT(cip);
  op_neg:
    pri = -pri;
    NEXT(cip);
  op_invert:
    pri = ~pri;
    NEXT(cip);
  op_add_c:
    GETPARAM(offs);
    pri += offs;
    NEXT(cip);
  op_smul_c:
    GETPARAM(offs);
    pri *= offs;
    NEXT(cip);
  op_zero_pri:
    pri = 0;
    NEXT(cip);
  op_zero_alt:
    alt = 0;
    NEXT(cip);
  op_zero:
    GETPARAM(offs);
    if ((int)offs == 0) CHKNAUGHT();
    _W(data, offs, 0);
    NEXT(cip);
  op_zero_s:
    GETPARAM(offs);
    if ((int)(frm + offs) == 0) CHKNAUGHT();
    _W(data, frm + offs, 0);
    NEXT(cip);
  op_sign_pri:
    if ((pri & 0xff) >= 0x80)
      pri |= ~(ucell)0xff;
    NEXT(cip);
  op_sign_alt:
    if ((alt & 0xff) >= 0x80)
      alt |= ~(ucell)0xff;
    NEXT(cip);
  op_eq:
    pri = (pri == alt) ? 1 : 0;
    NEXT(cip);
  op_neq:
    pri = (pri != alt) ? 1 : 0;
    NEXT(cip);
  op_less:
    pri = ((ucell)pri < (ucell)alt) ? 1 : 0;
    NEXT(cip);
  op_leq:
    pri = ((ucell)pri <= (ucell)alt) ? 1 : 0;
    NEXT(cip);
  op_grtr:
    pri = ((ucell)pri > (ucell)alt) ? 1 : 0;
    NEXT(cip);
  op_geq:
    pri = ((ucell)pri >= (ucell)alt) ? 1 : 0;
    NEXT(cip);
  op_sless:
    pri = (pri < alt) ? 1 : 0;
    NEXT(cip);
  op_sleq:
    pri = (pri <= alt) ? 1 : 0;
    NEXT(cip);
  op_sgrtr:
    pri = (pri > alt) ? 1 : 0;
    NEXT(cip);
  op_sgeq:
    pri = (pri >= alt) ? 1 : 0;
    NEXT(cip);
  op_eq_c_pri:
    GETPARAM(offs);
    pri = (pri == offs) ? 1 : 0;
    NEXT(cip);
  op_eq_c_alt:
    GETPARAM(offs);
    pri = (alt == offs) ? 1 : 0;
    NEXT(cip);
  op_inc_pri:
    pri++;
    NEXT(cip);
  op_inc_alt:
    alt++;
    NEXT(cip);
  op_inc:
    GETPARAM(offs);
    if ((int)offs == 0) CHKNAUGHT();
    _W(data, offs, _R(data, offs) + 1);
    NEXT(cip);
  op_inc_s:
    GETPARAM(offs);
    if ((int)(frm + offs) == 0) CHKNAUGHT();
    _W(data, frm + offs, _R(data, frm + offs) + 1);
    NEXT(cip);
  op_inc_i:
    if ((int)pri == 0) CHKNAUGHT();
    _W(data, pri, _R(data, pri) + 1);
    NEXT(cip);
  op_dec_pri:
    pri--;
    NEXT(cip);
  op_dec_alt:
    alt--;
    NEXT(cip);
  op_dec:
    GETPARAM(offs);
    if ((int)offs == 0) CHKNAUGHT();
    _W(data, offs, _R(data, offs) - 1);
    NEXT(cip);
  op_dec_s:
    GETPARAM(offs);
    if ((int)(frm + offs) == 0) CHKNAUGHT();
    _W(data, frm + offs, _R(data, frm + offs) - 1);
    NEXT(cip);
  op_dec_i:
    if ((int)pri == 0) CHKNAUGHT();
    _W(data, pri, _R(data, pri) - 1);
    NEXT(cip);
  op_movs:
    GETPARAM(offs);
    CHKMEMBLOCK(pri, offs);
    CHKMEMBLOCK(alt, offs);
    if ((int)alt == 0 && offs > 0) CHKNAUGHT();
    if (offs > 0)
      memmove(data + (uintptr_t)alt, data + (uintptr_t)pri, (size_t)offs);
    NEXT(cip);
  op_cmps:
    GETPARAM(offs);
    CHKMEMBLOCK(pri, offs);
    CHKMEMBLOCK(alt, offs);
    pri = (offs > 0) ? memcmp(data + (uintptr_t)alt, data + (uintptr_t)pri, (size_t)offs) : 0;
    NEXT(cip);
  op_fill:
    GETPARAM(offs);
    CHKMEMBLOCK(alt, offs);
    if ((int)alt == 0 && offs > 0) CHKNAUGHT();
    for (i = (int)alt; (size_t)offs >= sizeof(cell); i += (int)sizeof(cell), offs -= (cell)sizeof(cell))
      _W(data, i, pri);
    NEXT(cip);
  op_halt:
    GETPARAM(offs);
    if (retval != NULL)
      *retval = pri;
    amx->frm = frm;
    amx->pri = pri;
    amx->alt = alt;
    if (offs != AMX_ERR_SLEEP) {
      ABORT(amx, (int)offs);
    } else {
      CD_SAVE_WATERMARKS();
      amx->cip = (cell)((unsigned char *)cip - code);
      amx->reset_stk = reset_stk;
      amx->reset_hea = reset_hea;
      return (int)offs;
    }
  op_bounds:
    GETPARAM(offs);
    if ((ucell)pri > (ucell)offs) {
      amx->cip = (cell)((unsigned char *)cip - code);
      ABORT(amx, AMX_ERR_BOUNDS);
    }
    NEXT(cip);
  op_sysreq_pri: {
    amx->cip = (cell)((unsigned char *)cip - code);
    amx->hea = hea;
    amx->frm = frm;
    amx->stk = stk;
    CD_TRACK_STK();
    CD_TRACK_HEA();
    CD_NATIVE_ENTER(pri, 0);
    num = amx->callback(amx, pri, &pri, (const cell *)(data + (uintptr_t)stk));
    CD_NATIVE_LEAVE();
    if (num != AMX_ERR_NONE) {
      if (num == AMX_ERR_SLEEP) {
        CD_SAVE_WATERMARKS();
        amx->pri = pri;
        amx->alt = alt;
        amx->reset_stk = reset_stk;
        amx->reset_hea = reset_hea;
        return num;
      }
      ABORT(amx, num);
    }
    NEXT(cip);
  }
  op_sysreq_c: {
    GETPARAM(offs);
    amx->cip = (cell)((unsigned char *)cip - code);
    amx->hea = hea;
    amx->frm = frm;
    amx->stk = stk;
    CD_TRACK_STK();
    CD_TRACK_HEA();
    CD_NATIVE_ENTER(offs, 0);
    num = amx->callback(amx, offs, &pri, (const cell *)(data + (uintptr_t)stk));
    CD_NATIVE_LEAVE();
    if (num != AMX_ERR_NONE) {
      if (num == AMX_ERR_SLEEP) {
        CD_SAVE_WATERMARKS();
        amx->pri = pri;
        amx->alt = alt;
        amx->reset_stk = reset_stk;
        amx->reset_hea = reset_hea;
        return num;
      }
      ABORT(amx, num);
    }
    NEXT(cip);
  }
  op_sysreq_d: {
    GETPARAM(offs);
    amx->cip = (cell)((unsigned char *)cip - code);
    amx->hea = hea;
    amx->frm = frm;
    amx->stk = stk;
    amx->error = AMX_ERR_NONE;
    CD_TRACK_STK();
    CD_TRACK_HEA();
    CD_NATIVE_ENTER(-1, (ucell)offs);
    pri = ((AMX_NATIVE)(uintptr_t)(ucell)offs)(amx, (const cell *)(data + (uintptr_t)stk));
    CD_NATIVE_LEAVE();
    if (amx->error != AMX_ERR_NONE) {
      num = amx->error;
      amx->error = AMX_ERR_NONE;
      if (num == AMX_ERR_SLEEP) {
        CD_SAVE_WATERMARKS();
        amx->pri = pri;
        amx->alt = alt;
        amx->reset_stk = reset_stk;
        amx->reset_hea = reset_hea;
        return num;
      }
      ABORT(amx, num);
    }
    NEXT(cip);
  }
  op_sysreq_n: {
    GETPARAM(offs);
    GETPARAM(val);
    PUSH(val);
    amx->cip = (cell)((unsigned char *)cip - code);
    amx->hea = hea;
    amx->frm = frm;
    amx->stk = stk;
    CD_TRACK_STK();
    CD_TRACK_HEA();
    CD_NATIVE_ENTER(offs, 0);
    num = amx->callback(amx, offs, &pri, (const cell *)(data + (uintptr_t)stk));
    CD_NATIVE_LEAVE();
    stk += val + (cell)sizeof(cell);
    if (num != AMX_ERR_NONE) {
      if (num == AMX_ERR_SLEEP) {
        CD_SAVE_WATERMARKS();
        amx->pri = pri;
        amx->alt = alt;
        amx->reset_stk = reset_stk;
        amx->reset_hea = reset_hea;
        return num;
      }
      ABORT(amx, num);
    }
    NEXT(cip);
  }
  op_sysreq_nd: {
    GETPARAM(offs);
    GETPARAM(val);
    PUSH(val);
    amx->cip = (cell)((unsigned char *)cip - code);
    amx->hea = hea;
    amx->frm = frm;
    amx->stk = stk;
    amx->error = AMX_ERR_NONE;
    CD_TRACK_STK();
    CD_TRACK_HEA();
    CD_NATIVE_ENTER(-1, (ucell)offs);
    pri = ((AMX_NATIVE)(uintptr_t)(ucell)offs)(amx, (const cell *)(data + (uintptr_t)stk));
    CD_NATIVE_LEAVE();
    stk += val + (cell)sizeof(cell);
    if (amx->error != AMX_ERR_NONE) {
      num = amx->error;
      amx->error = AMX_ERR_NONE;
      if (num == AMX_ERR_SLEEP) {
        CD_SAVE_WATERMARKS();
        amx->pri = pri;
        amx->alt = alt;
        amx->reset_stk = reset_stk;
        amx->reset_hea = reset_hea;
        return num;
      }
      ABORT(amx, num);
    }
    NEXT(cip);
  }
  op_file:
    ABORT(amx, AMX_ERR_INVINSTR);
  op_line:
    SKIPPARAM(2);
    NEXT(cip);
  op_symbol:
    GETPARAM(offs);
    cip = (cell *)((unsigned char *)cip + (int)offs);
    NEXT(cip);
  op_srange:
    SKIPPARAM(2);
    NEXT(cip);
  op_symtag:
    SKIPPARAM(1);
    NEXT(cip);
  op_jump_pri: {
    if ((ucell)pri >= codesize)
      ABORT(amx, AMX_ERR_MEMACCESS);
    cell *dest_ = (cell *)(code + (uintptr_t)pri);
    CHECK_LCT_JUMP(dest_);
    cip = dest_;
    NEXT(cip);
  }
  op_switch: {
    cell *cptr = JUMPABS(code, cip) + 1;
    cip = JUMPABS(code, cptr + 1);
    num = ((int)*cptr) - 1;
    i = 0;
    while (i <= num) {
      offs = (i + num) / 2;
      val = *(cptr + offs * 2 + 2) - pri;
      if (val < 0) {
        i = (int)offs + 1;
      } else if (val > 0) {
        num = (int)offs - 1;
      } else {
        cip = JUMPABS(code, cptr + offs * 2 + 3);
        break;
      }
    }
    NEXT(cip);
  }
  op_casetbl:
    ABORT(amx, AMX_ERR_INVINSTR);
  op_swap_pri:
    offs = _R(data, stk);
    _W(data, stk, pri);
    pri = offs;
    NEXT(cip);
  op_swap_alt:
    offs = _R(data, stk);
    _W(data, stk, alt);
    alt = offs;
    NEXT(cip);
  op_push_adr:
    GETPARAM(offs);
    PUSH(frm + offs);
    NEXT(cip);
  op_nop:
    NEXT(cip);
  op_break:
    if (amx->debug != NULL) {
      amx->frm = frm;
      amx->stk = stk;
      amx->hea = hea;
      amx->cip = (cell)((unsigned char *)cip - code);
      num = amx->debug(amx);
      if (num != AMX_ERR_NONE) {
        if (num == AMX_ERR_SLEEP) {
          CD_SAVE_WATERMARKS();
          amx->pri = pri;
          amx->alt = alt;
          amx->reset_stk = reset_stk;
          amx->reset_hea = reset_hea;
          return num;
        }
        ABORT(amx, num);
      }
    }
    NEXT(cip);
  op_push5:
    GETPARAM(offs); PUSH(_R(data, offs));
    /* fallthrough */
  op_push4:
    GETPARAM(offs); PUSH(_R(data, offs));
    /* fallthrough */
  op_push3:
    GETPARAM(offs); PUSH(_R(data, offs));
    /* fallthrough */
  op_push2:
    GETPARAM(offs); PUSH(_R(data, offs));
    GETPARAM(offs); PUSH(_R(data, offs));
    CD_TRACK_STK();
    NEXT(cip);
  op_push5_s:
    GETPARAM(offs); PUSH(_R(data, frm + offs));
    /* fallthrough */
  op_push4_s:
    GETPARAM(offs); PUSH(_R(data, frm + offs));
    /* fallthrough */
  op_push3_s:
    GETPARAM(offs); PUSH(_R(data, frm + offs));
    /* fallthrough */
  op_push2_s:
    GETPARAM(offs); PUSH(_R(data, frm + offs));
    GETPARAM(offs); PUSH(_R(data, frm + offs));
    CD_TRACK_STK();
    NEXT(cip);
  op_push5_c:
    GETPARAM(offs); PUSH(offs);
    /* fallthrough */
  op_push4_c:
    GETPARAM(offs); PUSH(offs);
    /* fallthrough */
  op_push3_c:
    GETPARAM(offs); PUSH(offs);
    /* fallthrough */
  op_push2_c:
    GETPARAM(offs); PUSH(offs);
    GETPARAM(offs); PUSH(offs);
    CD_TRACK_STK();
    NEXT(cip);
  op_push5_adr:
    GETPARAM(offs); PUSH(frm + offs);
    /* fallthrough */
  op_push4_adr:
    GETPARAM(offs); PUSH(frm + offs);
    /* fallthrough */
  op_push3_adr:
    GETPARAM(offs); PUSH(frm + offs);
    /* fallthrough */
  op_push2_adr:
    GETPARAM(offs); PUSH(frm + offs);
    GETPARAM(offs); PUSH(frm + offs);
    CD_TRACK_STK();
    NEXT(cip);
  op_load_both:
    GETPARAM(offs); pri = _R(data, offs);
    GETPARAM(offs); alt = _R(data, offs);
    NEXT(cip);
  op_load_s_both:
    GETPARAM(offs); pri = _R(data, frm + offs);
    GETPARAM(offs); alt = _R(data, frm + offs);
    NEXT(cip);
  op_const:
    GETPARAM(offs);
    GETPARAM(val);
    if ((int)offs == 0) CHKNAUGHT();
    _W(data, offs, val);
    NEXT(cip);
  op_const_s:
    GETPARAM(offs);
    GETPARAM(val);
    if ((int)(frm + offs) == 0) CHKNAUGHT();
    _W(data, frm + offs, val);
    NEXT(cip);
}

#endif /* (__GNUC__ && !__MINGW32__) && !__64BIT__ */

/* Standard C switch interpreter (Windows x86/x64, Linux x64, MinGW, and Linux x86 NO_RELOC fallback) */
static int amx_Exec_Switch(AMX *amx, cell *retval, int index)
{
  AMX_HEADER *hdr;
  AMX_FUNCPART *func;
  unsigned char *code, *data;
  cell pri, alt, stk, frm, hea;
  cell reset_stk, reset_hea, *cip;
  ucell codesize;
  int i, num;
  int is_v9;
  OPCODE op;
  cell offs, val;
  AMX_EXT_HOOKS *ext_hooks = NULL;
  AMX_LCT_CTL long_call_ctl = NULL;
  AMX_ADDR_0_CTL address_naught_ctl = NULL;

  assert(amx != NULL);
  if ((amx->flags & AMX_FLAG_BROWSE) == AMX_FLAG_BROWSE)
    return 0;
  if (amx->callback == NULL)
    return AMX_ERR_CALLBACK;
  if ((amx->flags & AMX_FLAG_RELOC) == 0)
    return AMX_ERR_INIT;
  if ((amx->flags & AMX_FLAG_NTVREG) == 0) {
    if ((num = amx_Register(amx, NULL, 0)) != AMX_ERR_NONE)
      return num;
  }

  hdr = (AMX_HEADER *)amx->base;
  assert(hdr->magic == AMX_MAGIC);
  codesize = (ucell)(hdr->dat - hdr->cod);
  code = amx->base + (uintptr_t)hdr->cod;
  data = (amx->data != NULL) ? amx->data : amx->base + (uintptr_t)hdr->dat;
  hea = amx->hea;
  stk = amx->stk;
  reset_stk = stk;
  reset_hea = hea;
  frm = alt = pri = 0;
  is_v9 = (hdr->file_version >= 9) || ((amx->flags & AMX_FLAG_SYSREQN) != 0);

  if (index == AMX_EXEC_MAIN) {
    if (hdr->cip < 0)
      return AMX_ERR_INDEX;
    cip = (cell *)(code + (uintptr_t)hdr->cip);
  } else if (index == AMX_EXEC_CONT) {
    frm = amx->frm;
    stk = amx->stk;
    hea = amx->hea;
    pri = amx->pri;
    alt = amx->alt;
    reset_stk = amx->reset_stk;
    reset_hea = amx->reset_hea;
    cip = (cell *)(code + (uintptr_t)amx->cip);
  } else if (index < 0) {
    return AMX_ERR_INDEX;
  } else {
    if (index >= (cell)NUMENTRIES(hdr, publics, natives))
      return AMX_ERR_INDEX;
    func = GETENTRY(hdr, publics, index);
    cip = (cell *)(code + (uintptr_t)func->address);
  }

  amx_GetExtHooks(amx, &ext_hooks);
  if (ext_hooks != NULL) {
    long_call_ctl = ext_hooks->long_call_ctl;
    address_naught_ctl = ext_hooks->address_naught_ctl;
  }

  CHKSTACK();
  CHKHEAP();

  if (index != AMX_EXEC_CONT) {
    reset_stk += amx->paramcount * (cell)sizeof(cell);
    PUSH(amx->paramcount * (cell)sizeof(cell));
    amx->paramcount = 0;
    PUSH(0);
    CD_TRACK_STK();
  }
  CHKMARGIN();

  for ( ;; ) {
    amx->cip = (cell)((unsigned char *)cip - code);
    op = (OPCODE)*cip++;
    switch (op) {
    case OP_LOAD_PRI:
      GETPARAM(offs);
      pri = _R(data, offs);
      break;
    case OP_LOAD_ALT:
      GETPARAM(offs);
      alt = _R(data, offs);
      break;
    case OP_LOAD_S_PRI:
      GETPARAM(offs);
      pri = _R(data, frm + offs);
      break;
    case OP_LOAD_S_ALT:
      GETPARAM(offs);
      alt = _R(data, frm + offs);
      break;
    case OP_LREF_PRI:
      GETPARAM(offs);
      offs = _R(data, offs);
      pri = _R(data, offs);
      break;
    case OP_LREF_ALT:
      GETPARAM(offs);
      offs = _R(data, offs);
      alt = _R(data, offs);
      break;
    case OP_LREF_S_PRI:
      amx->frm = frm;
      amx->stk = stk;
      GETPARAM(offs);
      offs = _R(data, frm + offs);
      pri = _R(data, offs);
      break;
    case OP_LREF_S_ALT:
      amx->frm = frm;
      amx->stk = stk;
      GETPARAM(offs);
      offs = _R(data, frm + offs);
      alt = _R(data, offs);
      break;
    case OP_LOAD_I:
      if ((pri >= hea && pri < stk) || (ucell)pri >= (ucell)amx->stp)
        ABORT(amx, AMX_ERR_MEMACCESS);
      pri = _R(data, pri);
      break;
    case OP_LODB_I:
      GETPARAM(offs);
      if ((pri >= hea && pri < stk) || (ucell)pri >= (ucell)amx->stp)
        ABORT(amx, AMX_ERR_MEMACCESS);
      switch ((int)offs) {
      case 1: pri = _R8(data, pri); break;
      case 2: pri = _R16(data, pri); break;
      case 4: pri = (cell)_R32(data, pri); break;
      }
      break;
    case OP_CONST_PRI:
      GETPARAM(pri);
      break;
    case OP_CONST_ALT:
      GETPARAM(alt);
      break;
    case OP_ADDR_PRI:
      GETPARAM(pri);
      pri += frm;
      break;
    case OP_ADDR_ALT:
      GETPARAM(alt);
      alt += frm;
      break;
    case OP_STOR_PRI:
      GETPARAM(offs);
      if ((int)offs == 0) CHKNAUGHT();
      _W(data, offs, pri);
      break;
    case OP_STOR_ALT:
      GETPARAM(offs);
      if ((int)offs == 0) CHKNAUGHT();
      _W(data, offs, alt);
      break;
    case OP_STOR_S_PRI:
      GETPARAM(offs);
      if ((int)(frm + offs) == 0) CHKNAUGHT();
      _W(data, frm + offs, pri);
      break;
    case OP_STOR_S_ALT:
      GETPARAM(offs);
      if ((int)(frm + offs) == 0) CHKNAUGHT();
      _W(data, frm + offs, alt);
      break;
    case OP_SREF_PRI:
      amx->frm = frm;
      amx->stk = stk;
      GETPARAM(offs);
      offs = _R(data, offs);
      if ((int)offs == 0) CHKNAUGHT();
      _W(data, offs, pri);
      break;
    case OP_SREF_ALT:
      amx->frm = frm;
      amx->stk = stk;
      GETPARAM(offs);
      offs = _R(data, offs);
      if ((int)offs == 0) CHKNAUGHT();
      _W(data, offs, alt);
      break;
    case OP_SREF_S_PRI:
      amx->frm = frm;
      amx->stk = stk;
      GETPARAM(offs);
      offs = _R(data, frm + offs);
      if ((int)offs == 0) CHKNAUGHT();
      _W(data, offs, pri);
      break;
    case OP_SREF_S_ALT:
      amx->frm = frm;
      amx->stk = stk;
      GETPARAM(offs);
      offs = _R(data, frm + offs);
      if ((int)offs == 0) CHKNAUGHT();
      _W(data, offs, alt);
      break;
    case OP_STOR_I:
      if ((alt >= hea && alt < stk) || (ucell)alt >= (ucell)amx->stp)
        ABORT(amx, AMX_ERR_MEMACCESS);
      if ((int)alt == 0) CHKNAUGHT();
      _W(data, alt, pri);
      break;
    case OP_STRB_I:
      GETPARAM(offs);
      if ((alt >= hea && alt < stk) || (ucell)alt >= (ucell)amx->stp)
        ABORT(amx, AMX_ERR_MEMACCESS);
      if ((int)alt == 0) CHKNAUGHT();
      switch ((int)offs) {
      case 1: _W8(data, alt, pri); break;
      case 2: _W16(data, alt, pri); break;
      case 4: _W32(data, alt, pri); break;
      }
      break;
    case OP_LIDX:
      offs = pri * (cell)sizeof(cell) + alt;
      if ((offs >= hea && offs < stk) || (ucell)offs >= (ucell)amx->stp)
        ABORT(amx, AMX_ERR_MEMACCESS);
      pri = _R(data, offs);
      break;
    case OP_LIDX_B:
      GETPARAM(offs);
      offs = (pri << (int)offs) + alt;
      if ((offs >= hea && offs < stk) || (ucell)offs >= (ucell)amx->stp)
        ABORT(amx, AMX_ERR_MEMACCESS);
      pri = _R(data, offs);
      break;
    case OP_IDXADDR:
      pri = pri * (cell)sizeof(cell) + alt;
      break;
    case OP_IDXADDR_B:
      GETPARAM(offs);
      pri = (pri << (int)offs) + alt;
      break;
    case OP_ALIGN_PRI:
      GETPARAM(offs);
      #if BYTE_ORDER==LITTLE_ENDIAN
        if ((size_t)offs < sizeof(cell))
          pri ^= (cell)sizeof(cell) - offs;
      #endif
      break;
    case OP_ALIGN_ALT:
      GETPARAM(offs);
      #if BYTE_ORDER==LITTLE_ENDIAN
        if ((size_t)offs < sizeof(cell))
          alt ^= (cell)sizeof(cell) - offs;
      #endif
      break;
    case OP_LCTRL:
      GETPARAM(offs);
      switch (offs) {
      case 0: pri = hdr->cod; break;
      case 1: pri = hdr->dat; break;
      case 2: pri = hea; break;
      case 3: pri = amx->stp; break;
      case 4: pri = stk; break;
      case 5: pri = frm; break;
      case 6: pri = (cell)((unsigned char *)cip - code); break;
      case 0xFE:
        pri = (long_call_ctl != NULL) ? long_call_ctl(amx, AMX_LCT_OPTION, AMX_LCT_OPTION_CURRENT) : 0;
        break;
      case 0xFF:
        if (ext_hooks == NULL)
          pri = 1 | 16 | 32 | 64;
        else
          pri = 1 | 32
              | ((long_call_ctl != NULL ? long_call_ctl(amx, AMX_LCT_OPTION, AMX_LCT_OPTION_ACTIVE) : 0) << 1)
              | 64
              | ((address_naught_ctl != NULL ? address_naught_ctl(amx, -1) : 0) << 7);
        break;
      }
      break;
    case OP_SCTRL:
      GETPARAM(offs);
      switch (offs) {
      case 0:
      case 1:
      case 3:
        break;
      case 2:
        hea = pri;
        CD_TRACK_HEA();
        break;
      case 4:
        stk = pri;
        CD_TRACK_STK();
        break;
      case 5:
        frm = pri;
        break;
      case 6:
        if ((ucell)pri >= codesize)
          ABORT(amx, AMX_ERR_MEMACCESS);
        cip = (cell *)(code + (uintptr_t)pri);
        break;
      case 0xFE:
        if (long_call_ctl != NULL)
          long_call_ctl(amx, AMX_LCT_SET_TIME, pri);
        break;
      case 0xFF:
        if (long_call_ctl != NULL && (pri & 32)) {
          if (pri & 2)
            long_call_ctl(amx, AMX_LCT_OPTION, AMX_LCT_OPTION_ENABLE);
          else if (pri & 4)
            long_call_ctl(amx, AMX_LCT_OPTION, AMX_LCT_OPTION_RESET);
          else if (pri & 8)
            long_call_ctl(amx, AMX_LCT_OPTION, AMX_LCT_OPTION_RESTART);
          else
            long_call_ctl(amx, AMX_LCT_OPTION, AMX_LCT_OPTION_DISABLE);
        }
        if (address_naught_ctl != NULL && (pri & 64)) {
          address_naught_ctl(amx, (pri & 128) ? 1 : 0);
        }
        break;
      }
      break;
    case OP_MOVE_PRI:
      pri = alt;
      break;
    case OP_MOVE_ALT:
      alt = pri;
      break;
    case OP_XCHG:
      offs = pri;
      pri = alt;
      alt = offs;
      break;
    case OP_PUSH_PRI:
      PUSH(pri);
      break;
    case OP_PUSH_ALT:
      PUSH(alt);
      break;
    case OP_PUSH_C:
      GETPARAM(offs);
      PUSH(offs);
      break;
    case OP_PUSH_R:
      GETPARAM(offs);
      while (offs--)
        PUSH(pri);
      CD_TRACK_STK();
      break;
    case OP_PUSH:
      GETPARAM(offs);
      PUSH(_R(data, offs));
      break;
    case OP_PUSH_S:
      GETPARAM(offs);
      PUSH(_R(data, frm + offs));
      break;
    case OP_POP_PRI:
      POP(pri);
      break;
    case OP_POP_ALT:
      POP(alt);
      break;
    case OP_STACK:
      GETPARAM(offs);
      alt = stk;
      stk += offs;
      CD_TRACK_STK();
      CHKMARGIN();
      CHKSTACK();
      break;
    case OP_HEAP:
      GETPARAM(offs);
      alt = hea;
      hea += offs;
      CD_TRACK_HEA();
      CHKMARGIN();
      CHKHEAP();
      break;
    case OP_PROC:
      PUSH(frm);
      frm = stk;
      CD_TRACK_STK();
      CHKMARGIN();
      break;
    case OP_RET:
      POP(frm);
      POP(offs);
      if ((ucell)offs >= codesize)
        ABORT(amx, AMX_ERR_MEMACCESS);
      cip = (cell *)(code + (uintptr_t)offs);
      break;
    case OP_RETN:
      POP(frm);
      POP(offs);
      if ((ucell)offs >= codesize)
        ABORT(amx, AMX_ERR_MEMACCESS);
      cip = (cell *)(code + (uintptr_t)offs);
      stk += _R(data, stk) + (cell)sizeof(cell);
      amx->stk = stk;
      break;
    case OP_CALL:
      PUSH((cell)(((unsigned char *)cip - code) + sizeof(cell)));
      cip = JUMPABS(code, cip);
      CD_WATERMARK();
      CHECK_LCT_CALL(2);
      break;
    case OP_CALL_PRI:
      if ((ucell)pri >= codesize)
        ABORT(amx, AMX_ERR_MEMACCESS);
      PUSH((cell)((unsigned char *)cip - code));
      cip = (cell *)(code + (uintptr_t)pri);
      CD_WATERMARK();
      CHECK_LCT_CALL(1);
      break;
    case OP_JUMP: {
      cell *dest_ = JUMPABS(code, cip);
      CHECK_LCT_JUMP(dest_);
      cip = dest_;
      break;
    }
    case OP_JREL: {
      offs = *cip;
      cell *dest_ = (cell *)((unsigned char *)cip + (int)offs + sizeof(cell));
      CHECK_LCT_JUMP(dest_);
      cip = dest_;
      break;
    }
    case OP_JZER:
      CD_COND_JUMP(pri == 0);
      break;
    case OP_JNZ:
      CD_COND_JUMP(pri != 0);
      break;
    case OP_JEQ:
      CD_COND_JUMP(pri == alt);
      break;
    case OP_JNEQ:
      CD_COND_JUMP(pri != alt);
      break;
    case OP_JLESS:
      CD_COND_JUMP((ucell)pri < (ucell)alt);
      break;
    case OP_JLEQ:
      CD_COND_JUMP((ucell)pri <= (ucell)alt);
      break;
    case OP_JGRTR:
      CD_COND_JUMP((ucell)pri > (ucell)alt);
      break;
    case OP_JGEQ:
      CD_COND_JUMP((ucell)pri >= (ucell)alt);
      break;
    case OP_JSLESS:
      CD_COND_JUMP(pri < alt);
      break;
    case OP_JSLEQ:
      CD_COND_JUMP(pri <= alt);
      break;
    case OP_JSGRTR:
      CD_COND_JUMP(pri > alt);
      break;
    case OP_JSGEQ:
      CD_COND_JUMP(pri >= alt);
      break;
    case OP_SHL:
      pri = (cell)((ucell)pri << ((ucell)alt & CD_SHIFT_MASK));
      break;
    case OP_SHR:
      pri = (cell)((ucell)pri >> ((ucell)alt & CD_SHIFT_MASK));
      break;
    case OP_SSHR:
      pri >>= ((ucell)alt & CD_SHIFT_MASK);
      break;
    case OP_SHL_C_PRI:
      GETPARAM(offs);
      pri = (cell)((ucell)pri << ((ucell)offs & CD_SHIFT_MASK));
      break;
    case OP_SHL_C_ALT:
      GETPARAM(offs);
      alt = (cell)((ucell)alt << ((ucell)offs & CD_SHIFT_MASK));
      break;
    case OP_SHR_C_PRI:
      GETPARAM(offs);
      pri = (cell)((ucell)pri >> ((ucell)offs & CD_SHIFT_MASK));
      break;
    case OP_SHR_C_ALT:
      GETPARAM(offs);
      alt = (cell)((ucell)alt >> ((ucell)offs & CD_SHIFT_MASK));
      break;
    case OP_SMUL:
      pri *= alt;
      break;
    case OP_SDIV:
      if (alt == 0)
        ABORT(amx, AMX_ERR_DIVIDE);
      if ((ucell)pri == ((ucell)1 << (8 * sizeof(cell) - 1)) && alt == -1)
        ABORT(amx, AMX_ERR_DOMAIN);
      offs = (pri % alt + alt) % alt;
      pri = (pri - offs) / alt;
      alt = offs;
      break;
    case OP_SDIV_ALT:
      if (pri == 0)
        ABORT(amx, AMX_ERR_DIVIDE);
      if ((ucell)alt == ((ucell)1 << (8 * sizeof(cell) - 1)) && pri == -1)
        ABORT(amx, AMX_ERR_DOMAIN);
      offs = (alt % pri + pri) % pri;
      pri = (alt - offs) / pri;
      alt = offs;
      break;
    case OP_UMUL:
      pri = (ucell)pri * (ucell)alt;
      break;
    case OP_UDIV:
      if (alt == 0)
        ABORT(amx, AMX_ERR_DIVIDE);
      offs = (ucell)pri % (ucell)alt;
      pri = (ucell)pri / (ucell)alt;
      alt = offs;
      break;
    case OP_UDIV_ALT:
      if (pri == 0)
        ABORT(amx, AMX_ERR_DIVIDE);
      offs = (ucell)alt % (ucell)pri;
      pri = (ucell)alt / (ucell)pri;
      alt = offs;
      break;
    case OP_ADD:
      pri += alt;
      break;
    case OP_SUB:
      pri -= alt;
      break;
    case OP_SUB_ALT:
      pri = alt - pri;
      break;
    case OP_AND:
      pri &= alt;
      break;
    case OP_OR:
      pri |= alt;
      break;
    case OP_XOR:
      pri ^= alt;
      break;
    case OP_NOT:
      pri = !pri;
      break;
    case OP_NEG:
      pri = -pri;
      break;
    case OP_INVERT:
      pri = ~pri;
      break;
    case OP_ADD_C:
      GETPARAM(offs);
      pri += offs;
      break;
    case OP_SMUL_C:
      GETPARAM(offs);
      pri *= offs;
      break;
    case OP_ZERO_PRI:
      pri = 0;
      break;
    case OP_ZERO_ALT:
      alt = 0;
      break;
    case OP_ZERO:
      GETPARAM(offs);
      if ((int)offs == 0) CHKNAUGHT();
      _W(data, offs, 0);
      break;
    case OP_ZERO_S:
      GETPARAM(offs);
      if ((int)(frm + offs) == 0) CHKNAUGHT();
      _W(data, frm + offs, 0);
      break;
    case OP_SIGN_PRI:
      if ((pri & 0xff) >= 0x80)
        pri |= ~(ucell)0xff;
      break;
    case OP_SIGN_ALT:
      if ((alt & 0xff) >= 0x80)
        alt |= ~(ucell)0xff;
      break;
    case OP_EQ:
      pri = (pri == alt) ? 1 : 0;
      break;
    case OP_NEQ:
      pri = (pri != alt) ? 1 : 0;
      break;
    case OP_LESS:
      pri = ((ucell)pri < (ucell)alt) ? 1 : 0;
      break;
    case OP_LEQ:
      pri = ((ucell)pri <= (ucell)alt) ? 1 : 0;
      break;
    case OP_GRTR:
      pri = ((ucell)pri > (ucell)alt) ? 1 : 0;
      break;
    case OP_GEQ:
      pri = ((ucell)pri >= (ucell)alt) ? 1 : 0;
      break;
    case OP_SLESS:
      pri = (pri < alt) ? 1 : 0;
      break;
    case OP_SLEQ:
      pri = (pri <= alt) ? 1 : 0;
      break;
    case OP_SGRTR:
      pri = (pri > alt) ? 1 : 0;
      break;
    case OP_SGEQ:
      pri = (pri >= alt) ? 1 : 0;
      break;
    case OP_EQ_C_PRI:
      GETPARAM(offs);
      pri = (pri == offs) ? 1 : 0;
      break;
    case OP_EQ_C_ALT:
      GETPARAM(offs);
      pri = (alt == offs) ? 1 : 0;
      break;
    case OP_INC_PRI:
      pri++;
      break;
    case OP_INC_ALT:
      alt++;
      break;
    case OP_INC:
      GETPARAM(offs);
      if ((int)offs == 0) CHKNAUGHT();
      _W(data, offs, _R(data, offs) + 1);
      break;
    case OP_INC_S:
      GETPARAM(offs);
      if ((int)(frm + offs) == 0) CHKNAUGHT();
      _W(data, frm + offs, _R(data, frm + offs) + 1);
      break;
    case OP_INC_I:
      if ((int)pri == 0) CHKNAUGHT();
      _W(data, pri, _R(data, pri) + 1);
      break;
    case OP_DEC_PRI:
      pri--;
      break;
    case OP_DEC_ALT:
      alt--;
      break;
    case OP_DEC:
      GETPARAM(offs);
      if ((int)offs == 0) CHKNAUGHT();
      _W(data, offs, _R(data, offs) - 1);
      break;
    case OP_DEC_S:
      GETPARAM(offs);
      if ((int)(frm + offs) == 0) CHKNAUGHT();
      _W(data, frm + offs, _R(data, frm + offs) - 1);
      break;
    case OP_DEC_I:
      if ((int)pri == 0) CHKNAUGHT();
      _W(data, pri, _R(data, pri) - 1);
      break;
    case OP_MOVS:
      GETPARAM(offs);
      CHKMEMBLOCK(pri, offs);
      CHKMEMBLOCK(alt, offs);
      if ((int)alt == 0 && offs > 0) CHKNAUGHT();
      if (offs > 0)
        memmove(data + (uintptr_t)alt, data + (uintptr_t)pri, (size_t)offs);
      break;
    case OP_CMPS:
      GETPARAM(offs);
      CHKMEMBLOCK(pri, offs);
      CHKMEMBLOCK(alt, offs);
      pri = (offs > 0) ? memcmp(data + (uintptr_t)alt, data + (uintptr_t)pri, (size_t)offs) : 0;
      break;
    case OP_FILL:
      GETPARAM(offs);
      CHKMEMBLOCK(alt, offs);
      if ((int)alt == 0 && offs > 0) CHKNAUGHT();
      for (i = (int)alt; (size_t)offs >= sizeof(cell); i += (int)sizeof(cell), offs -= (cell)sizeof(cell))
        _W(data, i, pri);
      break;
    case OP_HALT:
      GETPARAM(offs);
      if (retval != NULL)
        *retval = pri;
      amx->frm = frm;
      amx->pri = pri;
      amx->alt = alt;
      if (offs != AMX_ERR_SLEEP) {
        ABORT(amx, (int)offs);
      } else {
        CD_SAVE_WATERMARKS();
        amx->cip = (cell)((unsigned char *)cip - code);
        amx->reset_stk = reset_stk;
        amx->reset_hea = reset_hea;
        return (int)offs;
      }
    case OP_BOUNDS:
      GETPARAM(offs);
      if ((ucell)pri > (ucell)offs) {
        amx->cip = (cell)((unsigned char *)cip - code);
        ABORT(amx, AMX_ERR_BOUNDS);
      }
      break;
    case OP_SYSREQ_PRI: {
      amx->cip = (cell)((unsigned char *)cip - code);
      amx->hea = hea;
      amx->frm = frm;
      amx->stk = stk;
      CD_TRACK_STK();
      CD_TRACK_HEA();
      CD_NATIVE_ENTER(pri, 0);
      num = amx->callback(amx, pri, &pri, (const cell *)(data + (uintptr_t)stk));
      CD_NATIVE_LEAVE();
      if (num != AMX_ERR_NONE) {
        if (num == AMX_ERR_SLEEP) {
          CD_SAVE_WATERMARKS();
          amx->pri = pri;
          amx->alt = alt;
          amx->reset_stk = reset_stk;
          amx->reset_hea = reset_hea;
          return num;
        }
        ABORT(amx, num);
      }
      break;
    }
    case OP_SYSREQ_C: {
      GETPARAM(offs);
      amx->cip = (cell)((unsigned char *)cip - code);
      amx->hea = hea;
      amx->frm = frm;
      amx->stk = stk;
      CD_TRACK_STK();
      CD_TRACK_HEA();
      CD_NATIVE_ENTER(offs, 0);
      num = amx->callback(amx, offs, &pri, (const cell *)(data + (uintptr_t)stk));
      CD_NATIVE_LEAVE();
      if (num != AMX_ERR_NONE) {
        if (num == AMX_ERR_SLEEP) {
          CD_SAVE_WATERMARKS();
          amx->pri = pri;
          amx->alt = alt;
          amx->reset_stk = reset_stk;
          amx->reset_hea = reset_hea;
          return num;
        }
        ABORT(amx, num);
      }
      break;
    }
    case OP_SYSREQ_N: /* Dual opcode 135: OP_SYSREQ_N (v9+) vs OP_SYSREQ_D (v6..8 32-bit) */
      if (is_v9) {
        GETPARAM(offs);
        GETPARAM(val);
        PUSH(val);
        amx->cip = (cell)((unsigned char *)cip - code);
        amx->hea = hea;
        amx->frm = frm;
        amx->stk = stk;
        CD_TRACK_STK();
        CD_TRACK_HEA();
        CD_NATIVE_ENTER(offs, 0);
        num = amx->callback(amx, offs, &pri, (const cell *)(data + (uintptr_t)stk));
        CD_NATIVE_LEAVE();
        stk += val + (cell)sizeof(cell);
        if (num != AMX_ERR_NONE) {
          if (num == AMX_ERR_SLEEP) {
            CD_SAVE_WATERMARKS();
            amx->pri = pri;
            amx->alt = alt;
            amx->reset_stk = reset_stk;
            amx->reset_hea = reset_hea;
            return num;
          }
          ABORT(amx, num);
        }
      } else {
        #if defined AMX_WIDE_POINTERS
          ABORT(amx, AMX_ERR_INVINSTR);
        #else
          GETPARAM(offs);
          amx->cip = (cell)((unsigned char *)cip - code);
          amx->hea = hea;
          amx->frm = frm;
          amx->stk = stk;
          amx->error = AMX_ERR_NONE;
          CD_TRACK_STK();
          CD_TRACK_HEA();
          CD_NATIVE_ENTER(-1, (ucell)offs);
          pri = ((AMX_NATIVE)(uintptr_t)(ucell)offs)(amx, (const cell *)(data + (uintptr_t)stk));
          CD_NATIVE_LEAVE();
          if (amx->error != AMX_ERR_NONE) {
            num = amx->error;
            amx->error = AMX_ERR_NONE;
            if (num == AMX_ERR_SLEEP) {
              CD_SAVE_WATERMARKS();
              amx->pri = pri;
              amx->alt = alt;
              amx->reset_stk = reset_stk;
              amx->reset_hea = reset_hea;
              return num;
            }
            ABORT(amx, num);
          }
        #endif
      }
      break;
    case _OP_SYSREQ_D: {
      #if defined AMX_WIDE_POINTERS
        ABORT(amx, AMX_ERR_INVINSTR);
      #else
        GETPARAM(offs);
        amx->cip = (cell)((unsigned char *)cip - code);
        amx->hea = hea;
        amx->frm = frm;
        amx->stk = stk;
        amx->error = AMX_ERR_NONE;
        CD_TRACK_STK();
        CD_TRACK_HEA();
        CD_NATIVE_ENTER(-1, (ucell)offs);
        pri = ((AMX_NATIVE)(uintptr_t)(ucell)offs)(amx, (const cell *)(data + (uintptr_t)stk));
        CD_NATIVE_LEAVE();
        if (amx->error != AMX_ERR_NONE) {
          num = amx->error;
          amx->error = AMX_ERR_NONE;
          if (num == AMX_ERR_SLEEP) {
            CD_SAVE_WATERMARKS();
            amx->pri = pri;
            amx->alt = alt;
            amx->reset_stk = reset_stk;
            amx->reset_hea = reset_hea;
            return num;
          }
          ABORT(amx, num);
        }
      #endif
      break;
    }
    case _OP_SYSREQ_ND: {
      #if defined AMX_WIDE_POINTERS
        ABORT(amx, AMX_ERR_INVINSTR);
      #else
        GETPARAM(offs);
        GETPARAM(val);
        PUSH(val);
        amx->cip = (cell)((unsigned char *)cip - code);
        amx->hea = hea;
        amx->frm = frm;
        amx->stk = stk;
        amx->error = AMX_ERR_NONE;
        CD_TRACK_STK();
        CD_TRACK_HEA();
        CD_NATIVE_ENTER(-1, (ucell)offs);
        pri = ((AMX_NATIVE)(uintptr_t)(ucell)offs)(amx, (const cell *)(data + (uintptr_t)stk));
        CD_NATIVE_LEAVE();
        stk += val + (cell)sizeof(cell);
        if (amx->error != AMX_ERR_NONE) {
          num = amx->error;
          amx->error = AMX_ERR_NONE;
          if (num == AMX_ERR_SLEEP) {
            CD_SAVE_WATERMARKS();
            amx->pri = pri;
            amx->alt = alt;
            amx->reset_stk = reset_stk;
            amx->reset_hea = reset_hea;
            return num;
          }
          ABORT(amx, num);
        }
      #endif
      break;
    }
    case OP_LINE:
      SKIPPARAM(2);
      break;
    case OP_SYMBOL:
      GETPARAM(offs);
      cip = (cell *)((unsigned char *)cip + (int)offs);
      break;
    case OP_SRANGE:
      SKIPPARAM(2);
      break;
    case OP_SYMTAG:
      SKIPPARAM(1);
      break;
    case OP_JUMP_PRI: {
      if ((ucell)pri >= codesize)
        ABORT(amx, AMX_ERR_MEMACCESS);
      cell *dest_ = (cell *)(code + (uintptr_t)pri);
      CHECK_LCT_JUMP(dest_);
      cip = dest_;
      break;
    }
    case OP_SWITCH: {
      cell *cptr = JUMPABS(code, cip) + 1;
      cip = JUMPABS(code, cptr + 1);
      num = ((int)*cptr) - 1;
      i = 0;
      while (i <= num) {
        offs = (i + num) / 2;
        val = *(cptr + offs * 2 + 2) - pri;
        if (val < 0) {
          i = (int)offs + 1;
        } else if (val > 0) {
          num = (int)offs - 1;
        } else {
          cip = JUMPABS(code, cptr + offs * 2 + 3);
          break;
        }
      }
      break;
    }
    case OP_SWAP_PRI:
      offs = _R(data, stk);
      _W(data, stk, pri);
      pri = offs;
      break;
    case OP_SWAP_ALT:
      offs = _R(data, stk);
      _W(data, stk, alt);
      alt = offs;
      break;
    case OP_PUSH_ADR:
      GETPARAM(offs);
      PUSH(frm + offs);
      break;
    case OP_NOP:
      break;
    case OP_BREAK:
      if (amx->debug != NULL) {
        amx->frm = frm;
        amx->stk = stk;
        amx->hea = hea;
        amx->cip = (cell)((unsigned char *)cip - code);
        num = amx->debug(amx);
        if (num != AMX_ERR_NONE) {
          if (num == AMX_ERR_SLEEP) {
            CD_SAVE_WATERMARKS();
            amx->pri = pri;
            amx->alt = alt;
            amx->reset_stk = reset_stk;
            amx->reset_hea = reset_hea;
            return num;
          }
          ABORT(amx, num);
        }
      }
      break;
    case OP_PUSH5:
      GETPARAM(offs); PUSH(_R(data, offs));
      /* fallthrough */
    case OP_PUSH4:
      GETPARAM(offs); PUSH(_R(data, offs));
      /* fallthrough */
    case OP_PUSH3:
      GETPARAM(offs); PUSH(_R(data, offs));
      /* fallthrough */
    case OP_PUSH2:
      GETPARAM(offs); PUSH(_R(data, offs));
      GETPARAM(offs); PUSH(_R(data, offs));
      CD_TRACK_STK();
      break;
    case OP_PUSH5_S:
      GETPARAM(offs); PUSH(_R(data, frm + offs));
      /* fallthrough */
    case OP_PUSH4_S:
      GETPARAM(offs); PUSH(_R(data, frm + offs));
      /* fallthrough */
    case OP_PUSH3_S:
      GETPARAM(offs); PUSH(_R(data, frm + offs));
      /* fallthrough */
    case OP_PUSH2_S:
      GETPARAM(offs); PUSH(_R(data, frm + offs));
      GETPARAM(offs); PUSH(_R(data, frm + offs));
      CD_TRACK_STK();
      break;
    case OP_PUSH5_C:
      GETPARAM(offs); PUSH(offs);
      /* fallthrough */
    case OP_PUSH4_C:
      GETPARAM(offs); PUSH(offs);
      /* fallthrough */
    case OP_PUSH3_C:
      GETPARAM(offs); PUSH(offs);
      /* fallthrough */
    case OP_PUSH2_C:
      GETPARAM(offs); PUSH(offs);
      GETPARAM(offs); PUSH(offs);
      CD_TRACK_STK();
      break;
    case OP_PUSH5_ADR:
      GETPARAM(offs); PUSH(frm + offs);
      /* fallthrough */
    case OP_PUSH4_ADR:
      GETPARAM(offs); PUSH(frm + offs);
      /* fallthrough */
    case OP_PUSH3_ADR:
      GETPARAM(offs); PUSH(frm + offs);
      /* fallthrough */
    case OP_PUSH2_ADR:
      GETPARAM(offs); PUSH(frm + offs);
      GETPARAM(offs); PUSH(frm + offs);
      CD_TRACK_STK();
      break;
    case OP_LOAD_BOTH:
      GETPARAM(offs); pri = _R(data, offs);
      GETPARAM(offs); alt = _R(data, offs);
      break;
    case OP_LOAD_S_BOTH:
      GETPARAM(offs); pri = _R(data, frm + offs);
      GETPARAM(offs); alt = _R(data, frm + offs);
      break;
    case OP_CONST:
      GETPARAM(offs);
      GETPARAM(val);
      if ((int)offs == 0) CHKNAUGHT();
      _W(data, offs, val);
      break;
    case OP_CONST_S:
      GETPARAM(offs);
      GETPARAM(val);
      if ((int)(frm + offs) == 0) CHKNAUGHT();
      _W(data, frm + offs, val);
      break;
    default:
      ABORT(amx, AMX_ERR_INVINSTR);
    }
  }
}

#if !(defined __GNUC__ && !defined __MINGW32__) || defined __64BIT__
int AMXAPI amx_Exec(AMX *amx, cell *retval, int index)
{
  return amx_Exec_Switch(amx, retval, index);
}
#endif

int AMXAPI amx_SetCallback(AMX *amx, AMX_CALLBACK callback)
{
  assert(amx != NULL);
  assert(callback != NULL);
  amx->callback = callback;
  return AMX_ERR_NONE;
}

int AMXAPI amx_SetDebugHook(AMX *amx, AMX_DEBUG debug)
{
  assert(amx != NULL);
  amx->debug = debug;
  return AMX_ERR_NONE;
}

int AMXAPI amx_RaiseError(AMX *amx, int error)
{
  assert(error > 0);
  amx->error = error;
  return AMX_ERR_NONE;
}

int AMXAPI amx_GetAddr(AMX *amx, cell amx_addr, cell **phys_addr)
{
  AMX_HEADER *hdr;
  unsigned char *data;

  assert(amx != NULL);
  hdr = (AMX_HEADER *)amx->base;
  assert(hdr != NULL);
  assert(hdr->magic == AMX_MAGIC);
  data = (amx->data != NULL) ? amx->data : amx->base + (uintptr_t)hdr->dat;

  assert(phys_addr != NULL);
  if ((amx_addr >= amx->hea && amx_addr < amx->stk) || amx_addr < 0 || amx_addr >= amx->stp) {
    *phys_addr = NULL;
    return AMX_ERR_MEMACCESS;
  }

  *phys_addr = (cell *)(data + (uintptr_t)amx_addr);
  return AMX_ERR_NONE;
}

int AMXAPI amx_MakeAddr(AMX *amx, cell *phys_addr, cell *amx_addr)
{
  AMX_HEADER *hdr;
  unsigned char *data;
  uintptr_t diff;

  if (amx == NULL || phys_addr == NULL || amx_addr == NULL)
    return AMX_ERR_PARAMS;
  hdr = (AMX_HEADER *)amx->base;
  data = (amx->data != NULL) ? amx->data : amx->base + (uintptr_t)hdr->dat;
  if ((unsigned char *)phys_addr < data)
    return AMX_ERR_MEMACCESS;
  diff = (uintptr_t)((unsigned char *)phys_addr - data);
  if (diff >= (uintptr_t)amx->stp || ((cell)diff >= amx->hea && (cell)diff < amx->stk))
    return AMX_ERR_MEMACCESS;
  *amx_addr = (cell)diff;
  return AMX_ERR_NONE;
}

int AMXAPI amx_Allot(AMX *amx, int cells, cell *amx_addr, cell **phys_addr)
{
  AMX_HEADER *hdr;
  unsigned char *data;

  assert(amx != NULL);
  hdr = (AMX_HEADER *)amx->base;
  assert(hdr != NULL);
  assert(hdr->magic == AMX_MAGIC);
  data = (amx->data != NULL) ? amx->data : amx->base + (uintptr_t)hdr->dat;

  if (amx->stk - amx->hea - cells * (cell)sizeof(cell) < STKMARGIN)
    return AMX_ERR_MEMORY;
  if (amx_addr != NULL)
    *amx_addr = amx->hea;
  if (phys_addr != NULL)
    *phys_addr = (cell *)(data + (uintptr_t)amx->hea);
  amx->hea += cells * (cell)sizeof(cell);
  return AMX_ERR_NONE;
}

int AMXAPI amx_Release(AMX *amx, cell amx_addr)
{
  if (amx->hea > amx_addr)
    amx->hea = amx_addr;
  return AMX_ERR_NONE;
}

int AMXAPI amx_StrLen(const cell *cstr, int *length)
{
  size_t len;
  #if BYTE_ORDER==LITTLE_ENDIAN
    cell c;
  #endif

  assert(length != NULL);
  if (cstr == NULL) {
    *length = 0;
    return AMX_ERR_PARAMS;
  }

  if ((ucell)*cstr > UNPACKEDMAX) {
    len = strlen((const char *)cstr);
    assert(check_endian());
    #if BYTE_ORDER==LITTLE_ENDIAN
      c = cstr[len / sizeof(cell)];
      len = len - len % sizeof(cell);
      while ((c & CHARMASK) != 0) {
        len++;
        c <<= 8 * sizeof(char);
      }
    #endif
  } else {
    for (len = 0; cstr[len] != 0; len++)
      /* nothing */;
  }
  *length = (int)len;
  return AMX_ERR_NONE;
}

int AMXAPI amx_StrSize(const cell *cstr, int *length)
{
  int err = amx_StrLen(cstr, length);
  if (err != AMX_ERR_NONE)
    return err;
  if ((ucell)*cstr > UNPACKEDMAX)
    *length = (*length + (int)sizeof(cell)) / (int)sizeof(cell);
  else
    *length = *length + 1;
  return AMX_ERR_NONE;
}

int AMXAPI amx_SetStringLen(cell *dest, const char *source, int length, int pack, int use_wchar, size_t size)
{
  size_t len, i;
  len = (size_t)length;
  if (pack) {
    if (size < UNLIMITED / sizeof(cell) && len >= size * sizeof(cell))
      len = size * sizeof(cell) - 1;
    dest[len / sizeof(cell)] = 0;
    if (use_wchar) {
      for (i = 0; i < len; i++)
        ((char *)dest)[i] = (char)(((const wchar_t *)source)[i]);
    } else {
      memcpy(dest, source, len);
    }
    #if BYTE_ORDER==LITTLE_ENDIAN
      len /= sizeof(cell);
      for (i = 0; i <= len; i++)
        swapcell((ucell *)&dest[i]);
    #endif
  } else {
    if (len >= size)
      len = size - 1;
    if (use_wchar) {
      for (i = 0; i < len; i++)
        dest[i] = (cell)(((const wchar_t *)source)[i]);
    } else {
      for (i = 0; i < len; i++)
        dest[i] = (cell)(unsigned char)source[i];
    }
    dest[len] = 0;
  }
  (void)0;
  return AMX_ERR_NONE;
}

int AMXAPI amx_SetString(cell *dest, const char *source, int pack, int use_wchar, size_t size)
{
  size_t length;
  assert(dest != NULL);
  assert(source != NULL);
  length = use_wchar ? wcslen((const wchar_t *)source) : strlen(source);
  return amx_SetStringLen(dest, source, (int)length, pack, use_wchar, size);
}

int AMXAPI amx_GetString(char *dest, const cell *source, int use_wchar, size_t size)
{
  int len = 0;
  if (dest == NULL || source == NULL || size == 0)
    return AMX_ERR_PARAMS;

  if ((ucell)*source > UNPACKEDMAX) {
    cell c = 0;
    size_t i = sizeof(cell) - 1;
    if (use_wchar) {
      wchar_t *wdest = (wchar_t *)dest;
      do {
        if (i == sizeof(cell) - 1)
          c = *source++;
        wdest[len] = (wchar_t)(unsigned char)(c >> (i * CHARBITS));
        i = (i + sizeof(cell) - 1) % sizeof(cell);
      } while (wdest[len++] != 0 && (size_t)len < size);
      if ((size_t)len >= size)
        wdest[size - 1] = 0;
      return AMX_ERR_NONE;
    } else {
      do {
        if (i == sizeof(cell) - 1)
          c = *source++;
        dest[len] = (char)(c >> (i * CHARBITS));
        i = (i + sizeof(cell) - 1) % sizeof(cell);
      } while (dest[len++] != 0 && (size_t)len < size);
    }
  } else {
    if (use_wchar) {
      wchar_t *wdest = (wchar_t *)dest;
      while (*source != 0 && (size_t)len < size)
        wdest[len++] = (wchar_t)*source++;
      if ((size_t)len >= size)
        len = (int)size - 1;
      wdest[len] = 0;
      return AMX_ERR_NONE;
    } else {
      while (*source != 0 && (size_t)len < size)
        dest[len++] = (char)*source++;
    }
  }
  if ((size_t)len >= size)
    len = (int)size - 1;
  if (len >= 0)
    dest[len] = '\0';
  return AMX_ERR_NONE;
}

int AMXAPI amx_UTF8Get(const char *string, const char **endptr, cell *value)
{
  static const char utf8_count[16] = { 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 3, 4 };
  static const long utf8_lowmark[5] = { 0x80, 0x800, 0x10000L, 0x200000L, 0x4000000L };
  unsigned char c;
  cell result;
  int followup;

  assert(string != NULL);
  if (value != NULL)
    *value = 0;
  if (endptr != NULL)
    *endptr = string;

  c = *(const unsigned char *)string++;
  if (c < 0x80) {
    result = c;
  } else {
    if (c < 0xc0 || c >= 0xfe)
      return AMX_ERR_PARAMS;
    followup = (int)utf8_count[(c >> 2) & 0x0f];
    result = c & (0x1f >> followup);
    switch (followup) {
    case 4:
      if (((c = *(const unsigned char *)string++) & 0xc0) != 0x80) return AMX_ERR_PARAMS;
      result = (result << 6) | (c & 0x3f);
      /* fallthrough */
    case 3:
      if (((c = *(const unsigned char *)string++) & 0xc0) != 0x80) return AMX_ERR_PARAMS;
      result = (result << 6) | (c & 0x3f);
      /* fallthrough */
    case 2:
      if (((c = *(const unsigned char *)string++) & 0xc0) != 0x80) return AMX_ERR_PARAMS;
      result = (result << 6) | (c & 0x3f);
      /* fallthrough */
    case 1:
      if (((c = *(const unsigned char *)string++) & 0xc0) != 0x80) return AMX_ERR_PARAMS;
      result = (result << 6) | (c & 0x3f);
      /* fallthrough */
    case 0:
      if (((c = *(const unsigned char *)string++) & 0xc0) != 0x80) return AMX_ERR_PARAMS;
      result = (result << 6) | (c & 0x3f);
      break;
    }
    if (result < utf8_lowmark[followup])
      return AMX_ERR_PARAMS;
    if ((result >= 0xd800 && result <= 0xdfff) || result == 0xfffe || result == 0xffff)
      return AMX_ERR_PARAMS;
  }

  if (value != NULL)
    *value = result;
  if (endptr != NULL)
    *endptr = string;
  return AMX_ERR_NONE;
}

int AMXAPI amx_UTF8Put(char *string, char **endptr, int maxchars, cell value)
{
  assert(string != NULL);
  if (endptr != NULL)
    *endptr = string;

  if (value < 0)
    return AMX_ERR_PARAMS;
  if (value < 0x80) {
    if (maxchars < 1) return AMX_ERR_PARAMS;
    *string++ = (char)value;
  } else if (value < 0x800) {
    if (maxchars < 2) return AMX_ERR_PARAMS;
    *string++ = (char)(((value >> 6) & 0x1f) | 0xc0);
    *string++ = (char)((value & 0x3f) | 0x80);
  } else if (value < 0x10000) {
    if (maxchars < 3) return AMX_ERR_PARAMS;
    if ((value >= 0xd800 && value <= 0xdfff) || value == 0xfffe || value == 0xffff)
      return AMX_ERR_PARAMS;
    *string++ = (char)(((value >> 12) & 0x0f) | 0xe0);
    *string++ = (char)(((value >> 6) & 0x3f) | 0x80);
    *string++ = (char)((value & 0x3f) | 0x80);
  } else if (value < 0x200000) {
    if (maxchars < 4) return AMX_ERR_PARAMS;
    *string++ = (char)(((value >> 18) & 0x07) | 0xf0);
    *string++ = (char)(((value >> 12) & 0x3f) | 0x80);
    *string++ = (char)(((value >> 6) & 0x3f) | 0x80);
    *string++ = (char)((value & 0x3f) | 0x80);
  } else if (value < 0x4000000) {
    if (maxchars < 5) return AMX_ERR_PARAMS;
    *string++ = (char)(((value >> 24) & 0x03) | 0xf8);
    *string++ = (char)(((value >> 18) & 0x3f) | 0x80);
    *string++ = (char)(((value >> 12) & 0x3f) | 0x80);
    *string++ = (char)(((value >> 6) & 0x3f) | 0x80);
    *string++ = (char)((value & 0x3f) | 0x80);
  } else {
    if (maxchars < 6) return AMX_ERR_PARAMS;
    *string++ = (char)(((value >> 30) & 0x01) | 0xfc);
    *string++ = (char)(((value >> 24) & 0x3f) | 0x80);
    *string++ = (char)(((value >> 18) & 0x3f) | 0x80);
    *string++ = (char)(((value >> 12) & 0x3f) | 0x80);
    *string++ = (char)(((value >> 6) & 0x3f) | 0x80);
    *string++ = (char)((value & 0x3f) | 0x80);
  }

  if (endptr != NULL)
    *endptr = string;
  return AMX_ERR_NONE;
}

int AMXAPI amx_UTF8Check(const char *string, int *length)
{
  int err = AMX_ERR_NONE;
  int len = 0;
  while (err == AMX_ERR_NONE && *string != '\0') {
    err = amx_UTF8Get(string, &string, NULL);
    if (err == AMX_ERR_NONE)
      len++;
  }
  if (length != NULL)
    *length = len;
  return err;
}

int AMXAPI amx_UTF8Len(const cell *cstr, int *length)
{
  int err;
  assert(length != NULL);
  err = amx_StrLen(cstr, length);
  if (err == AMX_ERR_NONE && (ucell)*cstr <= UNPACKEDMAX) {
    char buffer[10];
    char *endptr;
    int len = *length, count = 0;
    while (len-- > 0) {
      amx_UTF8Put(buffer, &endptr, (int)sizeof(buffer), *cstr++);
      count += (int)(endptr - buffer);
    }
    *length = count;
  }
  return err;
}

