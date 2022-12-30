//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#include "enclaveMemory.hpp"
#include <keystone_user.h>
#include <sys/stat.h>

namespace Keystone {

enclaveMemory::enclaveMemory() {
  epmFreeList   = 0;
  utmFreeList   = 0;
  rootPageTable = 0;
  startAddr     = 0;
}

void
enclaveMemory::startRuntimeMem() {
  runtimePhysAddr = getCurrentEPMAddress();
}

void
enclaveMemory::startEappMem() {
  eappPhysAddr = getCurrentEPMAddress();
}

void
enclaveMemory::startFreeMem() {
  freePhysAddr = getCurrentEPMAddress();
}

inline pte
enclaveMemory::pte_create(uintptr_t ppn, int type) {
  return __pte((ppn << PTE_PPN_SHIFT) | PTE_V | type);
}

inline pte
enclaveMemory::ptd_create(uintptr_t ppn) {
  return pte_create(ppn, PTE_V);
}

uintptr_t
enclaveMemory::pte_ppn(pte pte) {
  return pte_val(pte) >> PTE_PPN_SHIFT;
}

uintptr_t
enclaveMemory::ppn(uintptr_t addr) {
  return __pa(addr) >> RISCV_PGSHIFT;
}

size_t
enclaveMemory::pt_idx(uintptr_t addr, int level) {
  size_t idx = addr >> (RISCV_PGLEVEL_BITS * level + RISCV_PGSHIFT);
  return idx & ((1 << RISCV_PGLEVEL_BITS) - 1);
}

bool
enclaveMemory::allocPage(uintptr_t va, uintptr_t src, unsigned int mode) {
  uintptr_t page_addr;
  uintptr_t* pFreeList = (mode == UTM_FULL ? &utmFreeList : &epmFreeList);

  pte* pte = __ept_walk_create(va);

  /* if the page has been already allocated, return the page */
  if (pte_val(*pte) & PTE_V) {
    return true;
  }

  /* otherwise, allocate one from EPM freelist */
  page_addr = *pFreeList >> PAGE_BITS;
  *pFreeList += PAGE_SIZE;

  switch (mode) {
    case USER_NOEXEC: {
      *pte =
          pte_create(page_addr, PTE_D | PTE_A | PTE_R | PTE_W | PTE_U | PTE_V);
      break;
    }
    case RT_NOEXEC: {
      *pte = pte_create(page_addr, PTE_D | PTE_A | PTE_R | PTE_W | PTE_V);
      break;
    }
    case RT_FULL: {
      *pte =
          pte_create(page_addr, PTE_D | PTE_A | PTE_R | PTE_W | PTE_X | PTE_V);
      writeMem(src, (uintptr_t)page_addr << PAGE_BITS, PAGE_SIZE);
      break;
    }
    case USER_FULL: {
      *pte = pte_create(
          page_addr, PTE_D | PTE_A | PTE_R | PTE_W | PTE_X | PTE_U | PTE_V);
      writeMem(src, (uintptr_t)page_addr << PAGE_BITS, PAGE_SIZE);
      break;
    }
    case UTM_FULL: {
      assert(!src);
      *pte = pte_create(page_addr, PTE_D | PTE_A | PTE_R | PTE_W | PTE_V);
      break;
    }
    default: {
      PERROR("failed to add page - mode is invalid");
      return false;
    }
  }

  return true;
}

pte*
enclaveMemory::__ept_continue_walk_create(uintptr_t addr, pte* pte) {
  uint64_t free_ppn = ppn(epmFreeList);
  *pte              = ptd_create(free_ppn);
  epmFreeList += PAGE_SIZE;
  return __ept_walk_create(addr);
}

pte*
enclaveMemory::__ept_walk_internal(uintptr_t addr, int create) {
  pte* t = reinterpret_cast<pte*>(rootPageTable);

  int i;
  for (i = (VA_BITS - RISCV_PGSHIFT) / RISCV_PGLEVEL_BITS - 1; i > 0; i--) {
    size_t idx = pt_idx(addr, i);
    if (!(pte_val(t[idx]) & PTE_V)) {
      return create ? __ept_continue_walk_create(addr, &t[idx]) : 0;
    }

    t = reinterpret_cast<pte*>(readMem(
        reinterpret_cast<uintptr_t>(pte_ppn(t[idx]) << RISCV_PGSHIFT),
        PAGE_SIZE));
  }
  return &t[pt_idx(addr, 0)];
}

pte*
enclaveMemory::__ept_walk_create(uintptr_t addr) {
  return __ept_walk_internal(addr, 1);
}

pte*
enclaveMemory::__ept_walk(uintptr_t addr) {
  return __ept_walk_internal(addr, 0);
}

uintptr_t
enclaveMemory::epm_va_to_pa(uintptr_t addr) {
  pte* pte = __ept_walk(addr);
  if (pte)
    return pte_ppn(*pte) << RISCV_PGSHIFT;
  else
    return 0;
}

/* This function pre-allocates the required page tables so that
 * the virtual addresses are linearly mapped to the physical memory */
size_t
enclaveMemory::epmAllocVspace(uintptr_t addr, size_t num_pages) {
  size_t count;

  for (count = 0; count < num_pages; count++, addr += PAGE_SIZE) {
    pte* pte = __ept_walk_create(addr);
    if (!pte) break;
  }

  return count;
}

void
enclaveMemory::init(
    KeystoneDevice* dev, uintptr_t phys_addr, size_t min_pages) {
  pDevice = dev;
  // TODO(dayeol): need to set actual EPM size
  epmSize       = PAGE_SIZE * min_pages;
  rootPageTable = allocMem(PAGE_SIZE);
  epmFreeList   = phys_addr + PAGE_SIZE;
  startAddr     = phys_addr;
}

uintptr_t
enclaveMemory::allocUtm(size_t size) {
  uintptr_t ret = pDevice->initUTM(size);
  utmFreeList   = ret;
  untrustedSize = size;
  utmPhysAddr   = ret;
  return ret;
}

uintptr_t
enclaveMemory::allocPages(size_t page_num) {

  uintptr_t ret;
  ret = epmFreeList;
  epmFreeList = epmFreeList + PAGE_SIZE * page_num;
  return ret;
}

uintptr_t
enclaveMemory::allocMem(size_t size) {
  uintptr_t ret;

  assert(pDevice);

  ret = reinterpret_cast<uintptr_t>(pDevice->map(0, PAGE_SIZE));
  return ret;
}

uintptr_t
enclaveMemory::readMem(uintptr_t src, size_t size) {
  uintptr_t ret;

  assert(pDevice);

  ret = reinterpret_cast<uintptr_t>(pDevice->map(src - startAddr, size));
  return ret;
}

void
enclaveMemory::writeMem(uintptr_t src, uintptr_t dst, size_t size) {
  assert(pDevice);
  void* va_dst = pDevice->map(dst - startAddr, size);
  memcpy(va_dst, reinterpret_cast<void*>(src), size);
}

uintptr_t enclaveMemory::getMappedAddr(uintptr_t pa, size_t size){
  assert(pa >= startAddr);
  assert(pDevice);
  uintptr_t cur = pa - startAddr;
  uintptr_t end = pa - startAddr + size;
  void * va_start = 0;

  while (cur + PAGE_SIZE <= end) {
    void * va_dst = pDevice->map(pa - startAddr, PAGE_SIZE);
    cur += PAGE_SIZE;
    if(va_start == 0){
      va_start = va_dst;
    }
  }
  return (uintptr_t)va_start;
}
}  // namespace Keystone
