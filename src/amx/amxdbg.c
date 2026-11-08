/*  Pawn debugger interface
 *
 *  Support functions for debugger applications
 *
 *  Copyright (c) ITB CompuPhase, 2005-2006
 *  Modified for CrashDetect Plus (>64k lines/symbols, O(log N) binary search, safety fixes)
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

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "osdefs.h"
#include "amx.h"
#include "amxdbg.h"

#ifndef UINT16_MAX
  #define UINT16_MAX 0xffffu
#endif

int AMXAPI dbg_FreeInfo(AMX_DBG *amxdbg)
{
  assert(amxdbg != NULL);
  if (amxdbg->hdr != NULL)
    free(amxdbg->hdr);
  if (amxdbg->filetbl != NULL)
    free(amxdbg->filetbl);
  if (amxdbg->symboltbl != NULL)
    free(amxdbg->symboltbl);
  if (amxdbg->tagtbl != NULL)
    free(amxdbg->tagtbl);
  if (amxdbg->automatontbl != NULL)
    free(amxdbg->automatontbl);
  if (amxdbg->statetbl != NULL)
    free(amxdbg->statetbl);
  memset(amxdbg, 0, sizeof(AMX_DBG));
  return AMX_ERR_NONE;
}

static unsigned char *skip_symbol_entry(unsigned char *ptr, const unsigned char *end_ptr)
{
  uint16_t dim, d;
  if (ptr + sizeof(AMX_DBG_SYMBOL) > end_ptr)
    return NULL;
  dim = ((const AMX_DBG_SYMBOL *)ptr)->dim;
  #if BYTE_ORDER==BIG_ENDIAN
    amx_Align16(&dim);
  #endif
  ptr += sizeof(AMX_DBG_SYMBOL) - 1; /* point to name[0] */
  while (ptr < end_ptr && *ptr != '\0')
    ptr++;
  if (ptr >= end_ptr)
    return NULL;
  ptr++; /* skip '\0' */
  for (d = 0; d < dim; d++) {
    if (ptr + sizeof(AMX_DBG_SYMDIM) > end_ptr)
      return NULL;
    ptr += sizeof(AMX_DBG_SYMDIM);
  }
  return ptr;
}

int AMXAPI dbg_LoadInfo(AMX_DBG *amxdbg, FILE *fp)
{
  AMX_HEADER amxhdr;
  AMX_DBG_HDR dbghdr;
  unsigned char *ptr, *end_ptr, *linetbl_max_ptr;
  uint32_t index, real_lines, real_symbols;
  int dim;
  AMX_DBG_SYMDIM *symdim;
  ucell codesize;

  assert(fp != NULL);
  assert(amxdbg != NULL);

  memset(&amxhdr, 0, sizeof amxhdr);
  if (fseek(fp, 0L, SEEK_SET) != 0 || fread(&amxhdr, sizeof amxhdr, 1, fp) != 1)
    return AMX_ERR_FORMAT;

  #if BYTE_ORDER==BIG_ENDIAN
    amx_Align32((uint32_t*)&amxhdr.size);
    amx_Align16(&amxhdr.magic);
    amx_Align16((uint16_t*)&amxhdr.flags);
    amx_Align32((uint32_t*)&amxhdr.cod);
    amx_Align32((uint32_t*)&amxhdr.dat);
  #endif
  if (amxhdr.magic != AMX_MAGIC)
    return AMX_ERR_FORMAT;
  if ((amxhdr.flags & AMX_FLAG_DEBUG) == 0)
    return AMX_ERR_DEBUG;

  if (fseek(fp, amxhdr.size, SEEK_SET) != 0)
    return AMX_ERR_FORMAT;
  memset(&dbghdr, 0, sizeof(AMX_DBG_HDR));
  if (fread(&dbghdr, sizeof(AMX_DBG_HDR), 1, fp) != 1)
    return AMX_ERR_FORMAT;

  #if BYTE_ORDER==BIG_ENDIAN
    amx_Align32(&dbghdr.size);
    amx_Align16(&dbghdr.magic);
    amx_Align16(&dbghdr.flags);
    amx_Align16(&dbghdr.files);
    amx_Align16(&dbghdr.lines);
    amx_Align16(&dbghdr.symbols);
    amx_Align16(&dbghdr.tags);
    amx_Align16(&dbghdr.automatons);
    amx_Align16(&dbghdr.states);
  #endif
  if (dbghdr.magic != AMX_DBG_MAGIC || dbghdr.size < sizeof(AMX_DBG_HDR))
    return AMX_ERR_FORMAT;

  memset(amxdbg, 0, sizeof(AMX_DBG));
  amxdbg->hdr = (AMX_DBG_HDR *)malloc((size_t)dbghdr.size);
  if (dbghdr.files > 0)
    amxdbg->filetbl = (AMX_DBG_FILE **)malloc((size_t)dbghdr.files * sizeof(AMX_DBG_FILE *));
  if (dbghdr.tags > 0)
    amxdbg->tagtbl = (AMX_DBG_TAG **)malloc((size_t)dbghdr.tags * sizeof(AMX_DBG_TAG *));
  if (dbghdr.automatons > 0)
    amxdbg->automatontbl = (AMX_DBG_MACHINE **)malloc((size_t)dbghdr.automatons * sizeof(AMX_DBG_MACHINE *));
  if (dbghdr.states > 0)
    amxdbg->statetbl = (AMX_DBG_STATE **)malloc((size_t)dbghdr.states * sizeof(AMX_DBG_STATE *));

  if (amxdbg->hdr == NULL
      || (dbghdr.files > 0 && amxdbg->filetbl == NULL)
      || (dbghdr.tags > 0 && amxdbg->tagtbl == NULL)
      || (dbghdr.states > 0 && amxdbg->statetbl == NULL)
      || (dbghdr.automatons > 0 && amxdbg->automatontbl == NULL))
  {
    dbg_FreeInfo(amxdbg);
    return AMX_ERR_MEMORY;
  }

  memcpy(amxdbg->hdr, &dbghdr, sizeof dbghdr);
  if (dbghdr.size > sizeof(dbghdr)) {
    size_t body_size = (size_t)(dbghdr.size - sizeof(dbghdr));
    if (fread(amxdbg->hdr + 1, 1, body_size, fp) != body_size) {
      dbg_FreeInfo(amxdbg);
      return AMX_ERR_FORMAT;
    }
  }

  ptr = (unsigned char *)(amxdbg->hdr + 1);
  end_ptr = (unsigned char *)amxdbg->hdr + dbghdr.size;

  /* file table */
  for (index = 0; index < dbghdr.files; index++) {
    if (ptr + sizeof(AMX_DBG_FILE) > end_ptr) {
      dbg_FreeInfo(amxdbg);
      return AMX_ERR_FORMAT;
    }
    amxdbg->filetbl[index] = (AMX_DBG_FILE *)ptr;
    #if BYTE_ORDER==BIG_ENDIAN
      amx_AlignCell(&amxdbg->filetbl[index]->address);
    #endif
    ptr += sizeof(AMX_DBG_FILE) - 1;
    while (ptr < end_ptr && *ptr != '\0')
      ptr++;
    if (ptr >= end_ptr) {
      dbg_FreeInfo(amxdbg);
      return AMX_ERR_FORMAT;
    }
    ptr++; /* skip '\0' */
  }

  /* line table (with exact >65,535 uint16 overflow recovery) */
  amxdbg->linetbl = (AMX_DBG_LINE *)ptr;
  real_lines = (uint32_t)dbghdr.lines;
  if (ptr + (size_t)real_lines * sizeof(AMX_DBG_LINE) > end_ptr) {
    dbg_FreeInfo(amxdbg);
    return AMX_ERR_FORMAT;
  }

  #if BYTE_ORDER==BIG_ENDIAN
    for (index = 0; index < real_lines; index++) {
      amx_AlignCell(&amxdbg->linetbl[index].address);
      amx_Align32((uint32_t*)&amxdbg->linetbl[index].line);
    }
  #endif
  ptr += (size_t)real_lines * sizeof(AMX_DBG_LINE);

  linetbl_max_ptr = end_ptr
    - sizeof(AMX_DBG_SYMBOL) * (size_t)dbghdr.symbols
    - sizeof(AMX_DBG_TAG) * (size_t)dbghdr.tags
    - sizeof(AMX_DBG_MACHINE) * (size_t)dbghdr.automatons
    - sizeof(AMX_DBG_STATE) * (size_t)dbghdr.states;
  codesize = (ucell)(amxhdr.dat - amxhdr.cod);

  while (ptr + ((size_t)UINT16_MAX + 1u) * sizeof(AMX_DBG_LINE) <= linetbl_max_ptr) {
    AMX_DBG_LINE *chunk = (AMX_DBG_LINE *)ptr;
    ucell first_addr = chunk[0].address;
    ucell last_addr = chunk[UINT16_MAX].address;
    #if BYTE_ORDER==BIG_ENDIAN
      amx_AlignCell(&first_addr);
      amx_AlignCell(&last_addr);
    #endif
    if (real_lines > 0 && first_addr < amxdbg->linetbl[real_lines - 1].address)
      break;
    if (first_addr >= codesize || last_addr >= codesize || last_addr < first_addr)
      break;
    #if BYTE_ORDER==BIG_ENDIAN
      for (index = 0; index <= UINT16_MAX; index++) {
        amx_AlignCell(&chunk[index].address);
        amx_Align32((uint32_t*)&chunk[index].line);
      }
    #endif
    real_lines += (uint32_t)UINT16_MAX + 1u;
    ptr += ((size_t)UINT16_MAX + 1u) * sizeof(AMX_DBG_LINE);
  }
  amxdbg->real_lines = real_lines;
  if (real_lines > UINT16_MAX)
    amxdbg->hdr->lines = UINT16_MAX;

  /* symbol table (with >65,535 uint16 overflow recovery) */
  real_symbols = (uint32_t)dbghdr.symbols;
  {
    /* Probe if another 65,536 block of symbols exists before tags/automatons/states */
    unsigned char *probe = ptr;
    uint32_t s;
    int valid_initial = 1;
    for (s = 0; s < real_symbols; s++) {
      probe = skip_symbol_entry(probe, end_ptr);
      if (probe == NULL) {
        valid_initial = 0;
        break;
      }
    }
    if (!valid_initial) {
      dbg_FreeInfo(amxdbg);
      return AMX_ERR_FORMAT;
    }
    /* Check if probe hasn't reached the tag table yet due to 16-bit symbol overflow */
    while (probe < end_ptr) {
      unsigned char *probe2 = probe;
      int ok = 1;
      for (s = 0; s <= UINT16_MAX; s++) {
        const AMX_DBG_SYMBOL *sym = (const AMX_DBG_SYMBOL *)probe2;
        if (probe2 + sizeof(AMX_DBG_SYMBOL) > end_ptr) {
          ok = 0;
          break;
        }
        if (sym->ident != iVARIABLE && sym->ident != iREFERENCE
            && sym->ident != iARRAY && sym->ident != iREFARRAY
            && sym->ident != iFUNCTN) {
          ok = 0;
          break;
        }
        probe2 = skip_symbol_entry(probe2, end_ptr);
        if (probe2 == NULL) {
          ok = 0;
          break;
        }
      }
      if (!ok)
        break;
      real_symbols += (uint32_t)UINT16_MAX + 1u;
      probe = probe2;
    }
  }

  amxdbg->real_symbols = real_symbols;
  if (real_symbols > UINT16_MAX)
    amxdbg->hdr->symbols = UINT16_MAX;

  if (real_symbols > 0) {
    amxdbg->symboltbl = (AMX_DBG_SYMBOL **)malloc((size_t)real_symbols * sizeof(AMX_DBG_SYMBOL *));
    if (amxdbg->symboltbl == NULL) {
      dbg_FreeInfo(amxdbg);
      return AMX_ERR_MEMORY;
    }
  }

  for (index = 0; index < real_symbols; index++) {
    amxdbg->symboltbl[index] = (AMX_DBG_SYMBOL *)ptr;
    #if BYTE_ORDER==BIG_ENDIAN
      amx_AlignCell(&amxdbg->symboltbl[index]->address);
      amx_Align16(&amxdbg->symboltbl[index]->tag);
      amx_AlignCell(&amxdbg->symboltbl[index]->codestart);
      amx_AlignCell(&amxdbg->symboltbl[index]->codeend);
      amx_Align16(&amxdbg->symboltbl[index]->dim);
    #endif
    ptr += sizeof(AMX_DBG_SYMBOL) - 1;
    while (ptr < end_ptr && *ptr != '\0')
      ptr++;
    ptr++; /* skip '\0' */
    for (dim = 0; dim < (int)amxdbg->symboltbl[index]->dim; dim++) {
      symdim = (AMX_DBG_SYMDIM *)ptr;
      amx_Align16(&symdim->tag);
      amx_AlignCell(&symdim->size);
      ptr += sizeof(AMX_DBG_SYMDIM);
    }
  }

  /* tag name table */
  for (index = 0; index < dbghdr.tags; index++) {
    if (ptr + sizeof(AMX_DBG_TAG) > end_ptr)
      break;
    amxdbg->tagtbl[index] = (AMX_DBG_TAG *)ptr;
    #if BYTE_ORDER==BIG_ENDIAN
      amx_Align16(&amxdbg->tagtbl[index]->tag);
    #endif
    for (ptr = ptr + sizeof(AMX_DBG_TAG) - 1; ptr < end_ptr && *ptr != '\0'; ptr++)
      /* nothing */;
    if (ptr < end_ptr)
      ptr++;
  }

  /* automaton name table */
  for (index = 0; index < dbghdr.automatons; index++) {
    if (ptr + sizeof(AMX_DBG_MACHINE) > end_ptr)
      break;
    amxdbg->automatontbl[index] = (AMX_DBG_MACHINE *)ptr;
    #if BYTE_ORDER==BIG_ENDIAN
      amx_Align16(&amxdbg->automatontbl[index]->automaton);
      amx_AlignCell(&amxdbg->automatontbl[index]->address);
    #endif
    for (ptr = ptr + sizeof(AMX_DBG_MACHINE) - 1; ptr < end_ptr && *ptr != '\0'; ptr++)
      /* nothing */;
    if (ptr < end_ptr)
      ptr++;
  }

  /* state name table */
  for (index = 0; index < dbghdr.states; index++) {
    if (ptr + sizeof(AMX_DBG_STATE) > end_ptr)
      break;
    amxdbg->statetbl[index] = (AMX_DBG_STATE *)ptr;
    #if BYTE_ORDER==BIG_ENDIAN
      amx_Align16(&amxdbg->statetbl[index]->state);
      amx_Align16(&amxdbg->statetbl[index]->automaton);
    #endif
    for (ptr = ptr + sizeof(AMX_DBG_STATE) - 1; ptr < end_ptr && *ptr != '\0'; ptr++)
      /* nothing */;
    if (ptr < end_ptr)
      ptr++;
  }

  return AMX_ERR_NONE;
}

int AMXAPI dbg_LookupFile(AMX_DBG *amxdbg, ucell address, const char **filename)
{
  uint32_t low, high, count;

  assert(amxdbg != NULL);
  assert(filename != NULL);
  *filename = NULL;
  if (amxdbg->hdr == NULL || amxdbg->filetbl == NULL || amxdbg->hdr->files == 0)
    return AMX_ERR_NOTFOUND;

  count = (uint32_t)amxdbg->hdr->files;
  if (address < amxdbg->filetbl[0]->address)
    return AMX_ERR_NOTFOUND;

  /* O(log N) upper_bound - 1 binary search */
  low = 0;
  high = count;
  while (low < high) {
    uint32_t mid = low + (high - low) / 2;
    if (amxdbg->filetbl[mid]->address <= address)
      low = mid + 1;
    else
      high = mid;
  }
  if (low == 0)
    return AMX_ERR_NOTFOUND;

  *filename = amxdbg->filetbl[low - 1]->name;
  return AMX_ERR_NONE;
}

int AMXAPI dbg_LookupLine(AMX_DBG *amxdbg, ucell address, long *line)
{
  uint32_t low, high, count;

  assert(amxdbg != NULL);
  assert(line != NULL);
  *line = 0;
  if (amxdbg->hdr == NULL || amxdbg->linetbl == NULL)
    return AMX_ERR_NOTFOUND;

  count = amxdbg->real_lines ? amxdbg->real_lines : (uint32_t)amxdbg->hdr->lines;
  if (count == 0 || address < amxdbg->linetbl[0].address)
    return AMX_ERR_NOTFOUND;

  /* O(log N) upper_bound - 1 binary search across all 32-bit line entries */
  low = 0;
  high = count;
  while (low < high) {
    uint32_t mid = low + (high - low) / 2;
    if (amxdbg->linetbl[mid].address <= address)
      low = mid + 1;
    else
      high = mid;
  }
  if (low == 0)
    return AMX_ERR_NOTFOUND;

  *line = (long)amxdbg->linetbl[low - 1].line;
  return AMX_ERR_NONE;
}

int AMXAPI dbg_LookupFunction(AMX_DBG *amxdbg, ucell address, const char **funcname)
{
  uint32_t index, count;

  assert(amxdbg != NULL);
  assert(funcname != NULL);
  *funcname = NULL;
  if (amxdbg->hdr == NULL || amxdbg->symboltbl == NULL)
    return AMX_ERR_NOTFOUND;

  count = amxdbg->real_symbols ? amxdbg->real_symbols : (uint32_t)amxdbg->hdr->symbols;
  for (index = 0; index < count; index++) {
    if (amxdbg->symboltbl[index]->ident == iFUNCTN
        && amxdbg->symboltbl[index]->codestart <= address
        && amxdbg->symboltbl[index]->codeend > address) {
      *funcname = amxdbg->symboltbl[index]->name;
      return AMX_ERR_NONE;
    }
  }
  return AMX_ERR_NOTFOUND;
}

int AMXAPI dbg_GetTagName(AMX_DBG *amxdbg, int tag, const char **name)
{
  int index;

  assert(amxdbg != NULL);
  assert(name != NULL);
  *name = NULL;
  if (amxdbg->hdr == NULL || amxdbg->tagtbl == NULL)
    return AMX_ERR_NOTFOUND;

  for (index = 0; index < amxdbg->hdr->tags && amxdbg->tagtbl[index]->tag != (uint16_t)tag; index++)
    /* nothing */;
  if (index >= amxdbg->hdr->tags)
    return AMX_ERR_NOTFOUND;

  *name = amxdbg->tagtbl[index]->name;
  return AMX_ERR_NONE;
}

int AMXAPI dbg_GetAutomatonName(AMX_DBG *amxdbg, int automaton, const char **name)
{
  int index;

  assert(amxdbg != NULL);
  assert(name != NULL);
  *name = NULL;
  if (amxdbg->hdr == NULL || amxdbg->automatontbl == NULL)
    return AMX_ERR_NOTFOUND;

  for (index = 0; index < amxdbg->hdr->automatons && amxdbg->automatontbl[index]->automaton != (uint16_t)automaton; index++)
    /* nothing */;
  if (index >= amxdbg->hdr->automatons)
    return AMX_ERR_NOTFOUND;

  *name = amxdbg->automatontbl[index]->name;
  return AMX_ERR_NONE;
}

int AMXAPI dbg_GetStateName(AMX_DBG *amxdbg, int state, const char **name)
{
  int index;

  assert(amxdbg != NULL);
  assert(name != NULL);
  *name = NULL;
  if (amxdbg->hdr == NULL || amxdbg->statetbl == NULL)
    return AMX_ERR_NOTFOUND;

  for (index = 0; index < amxdbg->hdr->states && amxdbg->statetbl[index]->state != (uint16_t)state; index++)
    /* nothing */;
  if (index >= amxdbg->hdr->states)
    return AMX_ERR_NOTFOUND;

  *name = amxdbg->statetbl[index]->name;
  return AMX_ERR_NONE;
}

int AMXAPI dbg_GetLineAddress(AMX_DBG *amxdbg, long line, const char *filename, ucell *address)
{
  int file;
  uint32_t index, total_lines;
  ucell bottomaddr, topaddr;

  assert(amxdbg != NULL);
  assert(filename != NULL);
  assert(address != NULL);
  *address = 0;
  if (amxdbg->hdr == NULL)
    return AMX_ERR_NOTFOUND;

  total_lines = amxdbg->real_lines ? amxdbg->real_lines : (uint32_t)amxdbg->hdr->lines;
  index = 0;
  for (file = 0; file < amxdbg->hdr->files; file++) {
    if (strcmp(amxdbg->filetbl[file]->name, filename) != 0)
      continue;
    bottomaddr = amxdbg->filetbl[file]->address;
    topaddr = (file + 1 < amxdbg->hdr->files) ? amxdbg->filetbl[file + 1]->address : (ucell)(cell)-1;
    while (index < total_lines && amxdbg->linetbl[index].address < bottomaddr)
      index++;
    while (index < total_lines
           && amxdbg->linetbl[index].line < line
           && amxdbg->linetbl[index].address < topaddr)
      index++;
    if (index >= total_lines)
      return AMX_ERR_NOTFOUND;
    if (amxdbg->linetbl[index].line >= line && amxdbg->linetbl[index].address < topaddr)
      break;
  }

  if (file >= amxdbg->hdr->files || strcmp(amxdbg->filetbl[file]->name, filename) != 0)
    return AMX_ERR_NOTFOUND;

  *address = amxdbg->linetbl[index].address;
  return AMX_ERR_NONE;
}

int AMXAPI dbg_GetFunctionAddress(AMX_DBG *amxdbg, const char *funcname, const char *filename, ucell *address)
{
  uint32_t index, total_symbols, total_lines;
  int err;
  const char *tgtfile;
  ucell funcaddr;

  assert(amxdbg != NULL);
  assert(funcname != NULL);
  assert(filename != NULL);
  assert(address != NULL);
  *address = 0;
  if (amxdbg->hdr == NULL)
    return AMX_ERR_NOTFOUND;

  total_symbols = amxdbg->real_symbols ? amxdbg->real_symbols : (uint32_t)amxdbg->hdr->symbols;
  total_lines = amxdbg->real_lines ? amxdbg->real_lines : (uint32_t)amxdbg->hdr->lines;

  index = 0;
  for ( ;; ) {
    while (index < total_symbols
           && (amxdbg->symboltbl[index]->ident != iFUNCTN || strcmp(amxdbg->symboltbl[index]->name, funcname) != 0))
      index++;
    if (index >= total_symbols)
      return AMX_ERR_NOTFOUND;
    err = dbg_LookupFile(amxdbg, amxdbg->symboltbl[index]->address, &tgtfile);
    if (err == AMX_ERR_NONE && tgtfile != NULL && strcmp(filename, tgtfile) == 0)
      break;
    index++;
  }

  funcaddr = amxdbg->symboltbl[index]->address;
  for (index = 0; index < total_lines && amxdbg->linetbl[index].address < funcaddr; index++)
    /* nothing */;

  if (index >= total_lines)
    return AMX_ERR_NOTFOUND;
  *address = amxdbg->linetbl[index].address;
  return AMX_ERR_NONE;
}

int AMXAPI dbg_GetVariable(AMX_DBG *amxdbg, const char *symname, ucell scopeaddr, const AMX_DBG_SYMBOL **sym)
{
  ucell codestart, codeend;
  uint32_t index, total_symbols;

  assert(amxdbg != NULL);
  assert(symname != NULL);
  assert(sym != NULL);
  *sym = NULL;
  if (amxdbg->hdr == NULL || amxdbg->symboltbl == NULL)
    return AMX_ERR_NOTFOUND;

  total_symbols = amxdbg->real_symbols ? amxdbg->real_symbols : (uint32_t)amxdbg->hdr->symbols;
  codestart = codeend = 0;
  for (index = 0; index < total_symbols; index++) {
    const AMX_DBG_SYMBOL *cur = amxdbg->symboltbl[index];
    if (cur->ident == iFUNCTN)
      continue;
    if (cur->codestart > scopeaddr || cur->codeend < scopeaddr)
      continue;
    if (strcmp(cur->name, symname) == 0
        && ((codestart == 0 && codeend == 0)
            || (cur->codestart >= codestart && cur->codeend <= codeend)))
    {
      *sym = cur;
      codestart = cur->codestart;
      codeend = cur->codeend;
    }
  }

  return (*sym == NULL) ? AMX_ERR_NOTFOUND : AMX_ERR_NONE;
}

int AMXAPI dbg_GetArrayDim(AMX_DBG *amxdbg, const AMX_DBG_SYMBOL *sym, const AMX_DBG_SYMDIM **symdim)
{
  const char *ptr;

  assert(amxdbg != NULL);
  assert(sym != NULL);
  assert(symdim != NULL);
  *symdim = NULL;

  if (sym->ident != iARRAY && sym->ident != iREFARRAY)
    return AMX_ERR_PARAMS;
  assert(sym->dim > 0);

  for (ptr = sym->name; *ptr != '\0'; ptr++)
    /* nothing */;
  *symdim = (const AMX_DBG_SYMDIM *)(ptr + 1);

  return AMX_ERR_NONE;
}
