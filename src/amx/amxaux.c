/*  Support routines for the Pawn Abstract Machine
 *
 *  Copyright (c) ITB CompuPhase, 2003-2006
 *  Modified for CrashDetect Plus
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if defined _WIN32 || defined __WIN32__ || defined WIN32
  #ifndef WIN32_LEAN_AND_MEAN
    #define WIN32_LEAN_AND_MEAN
  #endif
  #include <windows.h>
#endif
#include "amx.h"
#include "amxaux.h"

static FILE *open_amx_file(const char *filename, const char *mode)
{
  if (filename == NULL || mode == NULL)
    return NULL;
#if defined _WIN32 || defined __WIN32__ || defined WIN32
  {
    wchar_t wmode[16];
    int wlen = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, filename, -1, NULL, 0);
    UINT cp = CP_UTF8;
    if (wlen <= 0) {
      cp = CP_ACP;
      wlen = MultiByteToWideChar(CP_ACP, 0, filename, -1, NULL, 0);
    }
    if (wlen > 0 && MultiByteToWideChar(CP_UTF8, 0, mode, -1, wmode, 16) > 0) {
      wchar_t *wpath = (wchar_t *)malloc((size_t)wlen * sizeof(wchar_t));
      if (wpath != NULL) {
        FILE *fp = NULL;
        if (MultiByteToWideChar(cp, 0, filename, -1, wpath, wlen) > 0)
          fp = _wfopen(wpath, wmode);
        free(wpath);
        if (fp != NULL)
          return fp;
      }
    }
  }
#endif
  return fopen(filename, mode);
}

size_t AMXAPI aux_ProgramSize(const char *filename)
{
  FILE *fp;
  AMX_HEADER hdr;

  if ((fp = open_amx_file(filename, "rb")) == NULL)
    return 0;
  if (fread(&hdr, sizeof hdr, 1, fp) != 1) {
    fclose(fp);
    return 0;
  }
  fclose(fp);

  amx_Align16(&hdr.magic);
  amx_Align32((uint32_t *)&hdr.stp);
  return (hdr.magic == AMX_MAGIC && hdr.stp > 0) ? (size_t)hdr.stp : 0;
}

int AMXAPI aux_LoadProgram(AMX *amx, const char *filename, void *memblock)
{
  FILE *fp;
  AMX_HEADER hdr;
  int result, didalloc;

  if ((fp = open_amx_file(filename, "rb")) == NULL)
    return AMX_ERR_NOTFOUND;
  if (fread(&hdr, sizeof hdr, 1, fp) != 1) {
    fclose(fp);
    return AMX_ERR_FORMAT;
  }
  amx_Align16(&hdr.magic);
  amx_Align16((uint16_t *)&hdr.flags);
  amx_Align32((uint32_t *)&hdr.size);
  amx_Align32((uint32_t *)&hdr.stp);
  if (hdr.magic != AMX_MAGIC || hdr.size <= 0 || hdr.stp < hdr.size) {
    fclose(fp);
    return AMX_ERR_FORMAT;
  }

  didalloc = 0;
  if (memblock == NULL) {
    if ((memblock = malloc((size_t)hdr.stp)) == NULL) {
      fclose(fp);
      return AMX_ERR_MEMORY;
    }
    didalloc = 1;
  }

  rewind(fp);
  if (fread(memblock, 1, (size_t)hdr.size, fp) != (size_t)hdr.size) {
    fclose(fp);
    if (didalloc)
      free(memblock);
    return AMX_ERR_FORMAT;
  }
  fclose(fp);

  memset(amx, 0, sizeof *amx);
  result = amx_Init(amx, memblock);

  if (result != AMX_ERR_NONE && didalloc) {
    free(memblock);
    amx->base = NULL;
  }

  return result;
}

int AMXAPI aux_FreeProgram(AMX *amx)
{
  if (amx->base != NULL) {
    amx_Cleanup(amx);
    free(amx->base);
    memset(amx, 0, sizeof(AMX));
  }
  return AMX_ERR_NONE;
}

const char * AMXAPI aux_StrError(int errnum)
{
  static const char * const messages[] = {
      /* AMX_ERR_NONE      */ "(none)",
      /* AMX_ERR_EXIT      */ "Forced exit",
      /* AMX_ERR_ASSERT    */ "Assertion failed",
      /* AMX_ERR_STACKERR  */ "Stack/heap collision (insufficient stack size)",
      /* AMX_ERR_BOUNDS    */ "Array index out of bounds",
      /* AMX_ERR_MEMACCESS */ "Invalid memory access",
      /* AMX_ERR_INVINSTR  */ "Invalid instruction",
      /* AMX_ERR_STACKLOW  */ "Stack underflow",
      /* AMX_ERR_HEAPLOW   */ "Heap underflow",
      /* AMX_ERR_CALLBACK  */ "No (valid) native function callback",
      /* AMX_ERR_NATIVE    */ "Native function failed",
      /* AMX_ERR_DIVIDE    */ "Divide by zero",
      /* AMX_ERR_SLEEP     */ "(sleep mode)",
      /* AMX_ERR_INVSTATE  */ "Invalid state",
      /* 14                */ "(reserved)",
      /* 15                */ "(reserved)",
      /* AMX_ERR_MEMORY    */ "Out of memory",
      /* AMX_ERR_FORMAT    */ "Invalid/unsupported P-code file format",
      /* AMX_ERR_VERSION   */ "File is for a newer version of the AMX",
      /* AMX_ERR_NOTFOUND  */ "File or function is not found",
      /* AMX_ERR_INDEX     */ "Invalid index parameter (bad entry point)",
      /* AMX_ERR_DEBUG     */ "Debugger cannot run",
      /* AMX_ERR_INIT      */ "AMX not initialized (or doubly initialized)",
      /* AMX_ERR_USERDATA  */ "Unable to set user data field (table full)",
      /* AMX_ERR_INIT_JIT  */ "Cannot initialize the JIT",
      /* AMX_ERR_PARAMS    */ "Parameter error",
      /* AMX_ERR_DOMAIN    */ "Domain error, expression result does not fit in range",
      /* AMX_ERR_GENERAL   */ "General error (unknown or unspecific error)",
      /* AMX_ERR_ADDRESS_0 */ "Wrote to banned address naught",
  };
  if (errnum < 0 || (size_t)errnum >= sizeof(messages) / sizeof(messages[0]))
    return "(unknown)";
  return messages[errnum];
}

int AMXAPI aux_GetSection(AMX *amx, int section, cell **start, size_t *size)
{
  AMX_HEADER *hdr;
  unsigned char *data;

  if (amx == NULL || amx->base == NULL || start == NULL || size == NULL)
    return AMX_ERR_PARAMS;

  hdr = (AMX_HEADER *)amx->base;
  data = (amx->data != NULL) ? amx->data : (amx->base + (uintptr_t)hdr->dat);

  switch (section) {
  case CODE_SECTION:
    *start = (cell *)(amx->base + (uintptr_t)hdr->cod);
    *size = (size_t)(hdr->dat - hdr->cod);
    break;
  case DATA_SECTION:
    *start = (cell *)data;
    *size = (size_t)(hdr->hea - hdr->dat);
    break;
  case HEAP_SECTION:
    *start = (cell *)(data + (uintptr_t)amx->hlw);
    *size = (amx->hea >= amx->hlw) ? (size_t)(amx->hea - amx->hlw) : 0;
    break;
  case STACK_SECTION:
    *start = (cell *)(data + (uintptr_t)amx->stk);
    *size = (amx->stp >= amx->stk) ? (size_t)(amx->stp - amx->stk) : 0;
    break;
  default:
    return AMX_ERR_PARAMS;
  }
  return AMX_ERR_NONE;
}
