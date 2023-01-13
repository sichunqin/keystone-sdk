//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#include "Enclave.hpp"
#include <math.h>
#include <sys/mman.h>
#include <sys/stat.h>
extern "C" {
#include "./keystone_user.h"
#include "common/sha3.h"
#include <stdlib.h>
}
#include "ElfFile.hpp"
#include "binFile.hpp"
#include "hash_util.hpp"


namespace Keystone {

static size_t
fstatFileSize(const char *path) {
  int rc;
  struct stat stat_buf;
  rc = stat(path, &stat_buf);
  return (rc == 0 ? stat_buf.st_size : 0);
}

Enclave::Enclave() {
  runtimeFile = NULL;
  enclaveFile = NULL;
  runtimeBinFile = NULL;
  eappBinFile = NULL;
}

Enclave::~Enclave() {
  if (runtimeFile) delete runtimeFile;
  if (enclaveFile) delete enclaveFile;
  destroy();
}

uint64_t
calculate_required_pages(uint64_t eapp_sz, uint64_t rt_sz) {
  uint64_t req_pages = 0;

  req_pages += ceil(eapp_sz / PAGE_SIZE);
  req_pages += ceil(rt_sz / PAGE_SIZE);

  /* FIXME: calculate the required number of pages for the page table.
   * We actually don't know how many page tables the enclave might need,
   * because the SDK never knows how its memory will be aligned.
   * Ideally, this should be managed by the driver.
   * For now, we naively allocate enough pages so that we can temporarily get
   * away from this problem.
   * 15 pages will be more than sufficient to cover several hundreds of
   * megabytes of enclave/runtime. */
  req_pages += 15;
  return req_pages;
}

Error
Enclave::loadUntrusted() {
  uintptr_t va_start = ROUND_DOWN(params.getUntrustedMem(), PAGE_BITS);
  uintptr_t va_end   = ROUND_UP(params.getUntrustedEnd(), PAGE_BITS);

  while (va_start < va_end) {
    if (!pMemory->allocPage(va_start, 0, UTM_FULL)) {
      return Error::PageAllocationFailure;
    }
    va_start += PAGE_SIZE;
  }
  return Error::Success;
}
Error
Enclave::allocateUntrusted() {
  uintptr_t va_start = ROUND_DOWN(params.getUntrustedMem(), PAGE_BITS);
  uintptr_t va_end   = ROUND_UP(params.getUntrustedEnd(), PAGE_BITS);

  while (va_start < va_end) {
    if (!pEMemory->allocPage(va_start, 0, UTM_FULL)) {
      return Error::PageAllocationFailure;
    }
    va_start += PAGE_SIZE;
  }
  return Error::Success;
}

/* This function will be deprecated when we implement freemem */
bool
Enclave::initStack(uintptr_t start, size_t size, bool is_rt) {
  static char nullpage[PAGE_SIZE] = {
      0,
  };
  uintptr_t high_addr    = ROUND_UP(start, PAGE_BITS);
  uintptr_t va_start_stk = ROUND_DOWN((high_addr - size), PAGE_BITS);
  int stk_pages          = (high_addr - va_start_stk) / PAGE_SIZE;

  for (int i = 0; i < stk_pages; i++) {
    if (!pMemory->allocPage(
            va_start_stk, (uintptr_t)nullpage,
            (is_rt ? RT_NOEXEC : USER_NOEXEC)))
      return false;

    va_start_stk += PAGE_SIZE;
  }

  return true;
}
/* This function will be deprecated when we implement freemem */
bool
Enclave::initializeStack(uintptr_t start, size_t size, bool is_rt) {

  static char nullpage[PAGE_SIZE] = {
      0,
  };
  uintptr_t high_addr    = ROUND_UP(start, PAGE_BITS);
  uintptr_t va_start_stk = ROUND_DOWN((high_addr - size), PAGE_BITS);
  int stk_pages          = (high_addr - va_start_stk) / PAGE_SIZE;

  for (int i = 0; i < stk_pages; i++) {
    if (!pEMemory->allocPage(
            va_start_stk, (uintptr_t)nullpage,
            (is_rt ? RT_NOEXEC : USER_NOEXEC)))
      return false;

    va_start_stk += PAGE_SIZE;
  }

  return true;
}


bool
Enclave::mapElf(ElfFile* elf) {
  uintptr_t va;

  assert(elf);

  size_t num_pages =
    ROUND_DOWN(elf->getTotalMemorySize(), PAGE_BITS) / PAGE_SIZE;
  va = elf->getMinVaddr();

  if (pMemory->epmAllocVspace(va, num_pages) != num_pages) {
    ERROR("failed to allocate vspace\n");
    return false;
  }
  return true;
}

bool
Enclave::mapRuntime() {
  size_t num_pages =
    ROUND_UP(RUNTIME_MEMORY_SIZE, PAGE_BITS) / PAGE_SIZE;
  if(!pEMemory->allocReservedPages(2) > 0)
    return false;
  pEMemory->startRuntimeMem();

  if(!pEMemory->allocReservedPages(num_pages) > 0)
    return false;
  return true;

}

bool Enclave::mapRuntimeBinFile(const char* path){

  runtimeBinFile = new binFile(path);
  if (!runtimeBinFile->isValid()) {
    ERROR("runtime file is not valid");
    destroy();
    return false;
  }

  size_t fsz = runtimeBinFile->getFileSize();
  assert(fsz <= RUNTIME_MEMORY_SIZE);

  size_t num_pages = ROUND_UP(RUNTIME_MEMORY_SIZE, PAGE_BITS) / PAGE_SIZE;
  if (pEMemory->epmAllocVspace(RUNTIME_ENTRY_VA, num_pages) != num_pages) {
    ERROR("Failed to allocate vspace for eapp\n");
    return false;
  }

  pEMemory->startRuntimeMem();

  uintptr_t va = RUNTIME_ENTRY_VA;
  uintptr_t src = (uintptr_t) runtimeBinFile->getPtr();

  while (va + PAGE_SIZE <= RUNTIME_ENTRY_VA + RUNTIME_MEMORY_SIZE) {
    if (!pEMemory->allocPage(va, (uintptr_t)src, RT_FULL))
      return false;
      src += PAGE_SIZE;
      va += PAGE_SIZE;
    }
  delete runtimeBinFile;
  runtimeBinFile = NULL;
  return true;
}

bool Enclave::mapEappBinFile(const char* path){

  eappBinFile = new binFile(path);
  if (!eappBinFile->isValid()) {
    ERROR("eapp file is not valid");
    destroy();
    return false;
  }

  uintptr_t page_start_va = ROUND_DOWN(EAPP_ENTRY_VA, PAGE_BITS);
  size_t fsz = eappBinFile->getFileSize();

  size_t num_pages = ROUND_UP(fsz + EAPP_ENTRY_VA - page_start_va, PAGE_BITS) / PAGE_SIZE; ;
  if (pEMemory->epmAllocVspace(page_start_va, num_pages) != num_pages) {
    ERROR("Failed to allocate vspace for eapp\n");
    return false;
  }

  pEMemory->startEappMem();

  uintptr_t va = EAPP_ENTRY_VA;
  uintptr_t src = (uintptr_t) eappBinFile->getPtr();

  if (!IS_ALIGNED(va, PAGE_SIZE)) {
    size_t offset = va - PAGE_DOWN(va);
    size_t length = PAGE_UP(va) - va;
    char page[PAGE_SIZE];
    memset(page, 0, PAGE_SIZE);
    memcpy(page + offset, (const void*)src, length);
    if (!pEMemory->allocPage(PAGE_DOWN(va), (uintptr_t)page, USER_FULL))
      return false;
    va += length;
    src += length;
  }

  while (va + PAGE_SIZE <= EAPP_ENTRY_VA + fsz) {
    if (!pEMemory->allocPage(va, (uintptr_t)src, USER_FULL))
      return false;

    src += PAGE_SIZE;
    va += PAGE_SIZE;
    }
  delete eappBinFile;
  eappBinFile = NULL;
  return true;
}
bool Enclave::loadEappElfFile(const char* path){
  if (enclaveFile) {
    ERROR("ELF files already initialized");
    return false;
  }

  enclaveFile = new ElfFile(path);

  if (!enclaveFile->initialize(false)) {
    ERROR("Invalid enclave ELF\n");
    destroy();
    return false;
  }

  if (!enclaveFile->isValid()) {
    ERROR("enclave file is not valid");
    destroy();
    return false;
  }

  pEMemory->allocReservedPages(2);

  pEMemory->startEappMem();

  static char nullpage[PAGE_SIZE] = {
      0,
  };

  ElfFile* elf = enclaveFile;
  unsigned int mode = elf->getPageMode();
  for (unsigned int i = 0; i < elf->getNumProgramHeaders(); i++) {
    if (elf->getProgramHeaderType(i) != PT_LOAD) {
      continue;
    }

    uintptr_t start      = elf->getProgramHeaderVaddr(i);

    uintptr_t file_end   = start + elf->getProgramHeaderFileSize(i);
    uintptr_t memory_end = start + elf->getProgramHeaderMemorySize(i);
    char* src            = reinterpret_cast<char*>(elf->getProgramSegment(i));
    uintptr_t va         = start;

    /* FIXME: This is a temporary fix for loading iozone binary
     * which has a page-misaligned program header. */
    if (!IS_ALIGNED(va, PAGE_SIZE)) {
      size_t offset = va - PAGE_DOWN(va);
      size_t length = PAGE_UP(va) - va;
      char page[PAGE_SIZE];
      memset(page, 0, PAGE_SIZE);
      memcpy(page + offset, (const void*)src, length);
      if (!pEMemory->copyPage((uintptr_t)page))
        return false;
      va += length;
      src += length;
    }

    /* first load all pages that do not include .bss segment */
    while (va + PAGE_SIZE <= file_end) {
      if (!pEMemory->copyPage((uintptr_t)src))
        return false;

      src += PAGE_SIZE;
      va += PAGE_SIZE;
    }

    /* next, load the page that has both initialized and uninitialized segments
     */
    if (va < file_end) {
      char page[PAGE_SIZE];
      memset(page, 0, PAGE_SIZE);
      memcpy(page, (const void*)src, static_cast<size_t>(file_end - va));
      if (!pEMemory->copyPage((uintptr_t)page))
        return false;
      va += PAGE_SIZE;
    }

    /* finally, load the remaining .bss segments */
    while (va < memory_end) {
      if (!pEMemory->copyPage((uintptr_t)nullpage))
        return false;
      va += PAGE_SIZE;
    }
  }

  return true;
}

bool Enclave::loadEappBinFile(const char* path){

  eappBinFile = new binFile(path);
  if (!eappBinFile->isValid()) {
    ERROR("eapp file is not valid");
    destroy();
    return false;
  }

  uintptr_t page_start_va = ROUND_DOWN(EAPP_ENTRY_VA, PAGE_BITS);
  size_t fsz = eappBinFile->getFileSize();

  size_t num_pages = ROUND_UP(fsz + EAPP_ENTRY_VA - page_start_va, PAGE_BITS) / PAGE_SIZE;

  pEMemory->allocReservedPages(2);

  pEMemory->startEappMem();

  uintptr_t va = EAPP_ENTRY_VA;
  uintptr_t src = (uintptr_t) eappBinFile->getPtr();

  if (!IS_ALIGNED(va, PAGE_SIZE)) {
    size_t offset = va - PAGE_DOWN(va);
    size_t length = PAGE_UP(va) - va;
    char page[PAGE_SIZE];
    memset(page, 0, PAGE_SIZE);
    memcpy(page + offset, (const void*)src, length);

    if (!pEMemory->copyPage((uintptr_t)page))
      return false;
    va += length;
    src += length;
  }

  while (va + PAGE_SIZE <= EAPP_ENTRY_VA + fsz) {
    if (!pEMemory->copyPage((uintptr_t)src))
      return false;
      src += PAGE_SIZE;
      va += PAGE_SIZE;
    }
  delete eappBinFile;
  eappBinFile = NULL;
  return true;
}


Error
Enclave::loadElf(ElfFile* elf) {
  static char nullpage[PAGE_SIZE] = {
      0,
  };

  unsigned int mode = elf->getPageMode();
  for (unsigned int i = 0; i < elf->getNumProgramHeaders(); i++) {
    if (elf->getProgramHeaderType(i) != PT_LOAD) {
      continue;
    }

    uintptr_t start      = elf->getProgramHeaderVaddr(i);
    uintptr_t file_end   = start + elf->getProgramHeaderFileSize(i);
    uintptr_t memory_end = start + elf->getProgramHeaderMemorySize(i);
    char* src            = reinterpret_cast<char*>(elf->getProgramSegment(i));
    uintptr_t va         = start;

    /* FIXME: This is a temporary fix for loading iozone binary
     * which has a page-misaligned program header. */
    if (!IS_ALIGNED(va, PAGE_SIZE)) {
      size_t offset = va - PAGE_DOWN(va);
      size_t length = PAGE_UP(va) - va;
      char page[PAGE_SIZE];
      memset(page, 0, PAGE_SIZE);
      memcpy(page + offset, (const void*)src, length);
      if (!pMemory->allocPage(PAGE_DOWN(va), (uintptr_t)page, mode))
        return Error::PageAllocationFailure;
      va += length;
      src += length;
    }

    /* first load all pages that do not include .bss segment */
    while (va + PAGE_SIZE <= file_end) {
      if (!pMemory->allocPage(va, (uintptr_t)src, mode))
        return Error::PageAllocationFailure;

      src += PAGE_SIZE;
      va += PAGE_SIZE;
    }

    /* next, load the page that has both initialized and uninitialized segments
     */
    if (va < file_end) {
      char page[PAGE_SIZE];
      memset(page, 0, PAGE_SIZE);
      memcpy(page, (const void*)src, static_cast<size_t>(file_end - va));
      if (!pMemory->allocPage(va, (uintptr_t)page, mode))
        return Error::PageAllocationFailure;
      va += PAGE_SIZE;
    }

    /* finally, load the remaining .bss segments */
    while (va < memory_end) {
      if (!pMemory->allocPage(va, (uintptr_t)nullpage, mode))
        return Error::PageAllocationFailure;
      va += PAGE_SIZE;
    }
  }

  return Error::Success;
}

Error
Enclave::validate_and_hash_enclave(struct runtime_params_t args) {
  hash_ctx_t hash_ctx;
  int ptlevel = RISCV_PGLEVEL_TOP;

  hash_init(&hash_ctx);

  // hash the runtime parameters
  hash_extend(&hash_ctx, &args, sizeof(struct runtime_params_t));

  uintptr_t runtime_max_seen = 0;
  uintptr_t user_max_seen    = 0;

  // hash the epm contents including the virtual addresses
  int valid = pMemory->validateAndHashEpm(
      &hash_ctx, ptlevel, reinterpret_cast<pte*>(pMemory->getRootPageTable()),
      0, 0, &runtime_max_seen, &user_max_seen);

  if (valid == -1) {
    return Error::InvalidEnclave;
  }

  hash_finalize(hash, &hash_ctx);

  return Error::Success;
}

bool
Enclave::initFiles(const char* eapppath, const char* runtimepath) {
  if (runtimeFile || enclaveFile) {
    ERROR("ELF files already initialized");
    return false;
  }

  runtimeFile = new ElfFile(runtimepath);
  enclaveFile = new ElfFile(eapppath);

  if (!runtimeFile->initialize(true)) {
    ERROR("Invalid runtime ELF\n");
    destroy();
    return false;
  }

  if (!enclaveFile->initialize(false)) {
    ERROR("Invalid enclave ELF\n");
    destroy();
    return false;
  }

  if (!runtimeFile->isValid()) {
    ERROR("runtime file is not valid");
    destroy();
    return false;
  }
  if (!enclaveFile->isValid()) {
    ERROR("enclave file is not valid");
    destroy();
    return false;
  }

  return true;
}

bool
Enclave::prepareEnclave(uintptr_t alternatePhysAddr) {
  // FIXME: this will be deprecated with complete freemem support.
  // We just add freemem size for now.
  uint64_t minPages;
  minPages = ROUND_UP(params.getFreeMemSize(), PAGE_BITS) / PAGE_SIZE;
  minPages += calculate_required_pages(
      enclaveFile->getTotalMemorySize(), runtimeFile->getTotalMemorySize());

  if (params.isSimulated()) {
    pMemory->init(0, 0, minPages);
    return true;
  }

  /* Call Enclave Driver */
  if (pDevice->create(minPages) != Error::Success) {
    return false;
  }

  /* We switch out the phys addr as needed */
  uintptr_t physAddr;
  if (alternatePhysAddr) {
    physAddr = alternatePhysAddr;
  } else {
    physAddr = pDevice->getPhysAddr();
  }

  pMemory->init(pDevice, physAddr, minPages);
  return true;
}

bool
Enclave::prepareMemory(uintptr_t alternatePhysAddr, const char *eappbinPath) {
  // FIXME: this will be deprecated with complete freemem support.
  // We just add freemem size for now.
  uint64_t minPages;
  minPages = ROUND_UP(params.getFreeMemSize(), PAGE_BITS) / PAGE_SIZE;
  eappbinSize = (uint64_t)fstatFileSize(eappbinPath);
  if(eappbinSize == 0){
    ERROR("Invalid enclave Bin file\n");
    return false;
  }
  minPages += calculate_required_pages(
      (uint64_t)eappbinSize, RUNTIME_MEMORY_SIZE);

  if (params.isSimulated()) {
    pMemory->init(0, 0, minPages);
    return true;
  }

  /* Call Enclave Driver */
  if (pDevice->create(minPages) != Error::Success) {
    return false;
  }

  /* We switch out the phys addr as needed */
  uintptr_t physAddr;
  if (alternatePhysAddr) {
    physAddr = alternatePhysAddr;
  } else {
    physAddr = pDevice->getPhysAddr();
  }

  pEMemory->init(pDevice, physAddr, minPages);
  return true;
}

Error
Enclave::init(const char* eapppath, Params _params) {
  const char* runtimepath = getenv("KEYSTONE_RUNTIME_PATH");
  return this->init(eapppath, runtimepath, _params, (uintptr_t)0);
}

Error
Enclave::init(const char* eapppath, const char* runtimepath, Params _params) {
  return this->init(eapppath, runtimepath, _params, (uintptr_t)0);
}

const char*
Enclave::getHash() {
  return this->hash;
}

Error
Enclave::init(
    const char* eapppath, const char* runtimepath, Params _params,
    uintptr_t alternatePhysAddr) {
  params = _params;

  if (params.isSimulated()) {
    pMemory = new SimulatedEnclaveMemory();
    pDevice = new MockKeystoneDevice();
  } else {
    pMemory = new PhysicalEnclaveMemory();
    pDevice = new KeystoneDevice();
  }

  if (!initFiles(eapppath, runtimepath)) {
    return Error::FileInitFailure;
  }

  if (!pDevice->initDevice(params)) {
    destroy();
    return Error::DeviceInitFailure;
  }

  if (!prepareEnclave(alternatePhysAddr)) {
    destroy();
    return Error::DeviceError;
  }

  if (!mapElf(runtimeFile)) {
    destroy();
    return Error::VSpaceAllocationFailure;
  }

  pMemory->startRuntimeMem();

  if (loadElf(runtimeFile) != Error::Success) {
    ERROR("failed to load runtime ELF");
    destroy();
    return Error::ELFLoadFailure;
  }

  if (!mapElf(enclaveFile)) {
    destroy();
    return Error::VSpaceAllocationFailure;
  }

  pMemory->startEappMem();

  if (loadElf(enclaveFile) != Error::Success) {
    ERROR("failed to load enclave ELF");
    destroy();
    return Error::ELFLoadFailure;
  }

/* initialize stack. If not using freemem */
#ifndef USE_FREEMEM
  if (!initStack(DEFAULT_STACK_START, DEFAULT_STACK_SIZE, 0)) {
    ERROR("failed to init static stack");
    destroy();
    return Error::PageAllocationFailure;
  }
#endif /* USE_FREEMEM */

  uintptr_t utm_free;
  utm_free = pMemory->allocUtm(params.getUntrustedSize());

  if (!utm_free) {
    ERROR("failed to init untrusted memory - ioctl() failed");
    destroy();
    return Error::DeviceError;
  }

  if (loadUntrusted() != Error::Success) {
    ERROR("failed to load untrusted");
  }

  struct runtime_params_t runtimeParams;
  runtimeParams.runtime_entry =
      reinterpret_cast<uintptr_t>(runtimeFile->getEntryPoint());
  runtimeParams.user_entry =
      reinterpret_cast<uintptr_t>(enclaveFile->getEntryPoint());
  runtimeParams.untrusted_ptr =
      reinterpret_cast<uintptr_t>(params.getUntrustedMem());
  runtimeParams.untrusted_size =
      reinterpret_cast<uintptr_t>(params.getUntrustedSize());

  pMemory->startFreeMem();

  /* TODO: This should be invoked with some other function e.g., measure() */
  if (params.isSimulated()) {
    validate_and_hash_enclave(runtimeParams);
  }

  if (pDevice->finalize(
          pMemory->getRuntimePhysAddr(), pMemory->getEappPhysAddr(),
          pMemory->getFreePhysAddr(), runtimeParams) != Error::Success) {
    destroy();
    return Error::DeviceError;
  }
  if (!mapUntrusted(params.getUntrustedSize())) {
    ERROR(
        "failed to finalize enclave - cannot obtain the untrusted buffer "
        "pointer \n");
    destroy();
    return Error::DeviceMemoryMapError;
  }
  //}

  /* ELF files are no longer needed */
  delete enclaveFile;
  delete runtimeFile;
  enclaveFile = NULL;
  runtimeFile = NULL;
  return Error::Success;
}

Error
Enclave::initialize(const char* eappBinPath, Params _params) {
  const char* runtimeBinPath = getenv("KEYSTONE_RUNTIME_BIN_PATH");
  return this->initialize(eappBinPath, runtimeBinPath, _params, (uintptr_t)0);
}
Error Enclave::initialize(const char* eappBinPath,const char* runtimeBinPath, Params _params, uintptr_t alternatePhysAddr){
  params = _params;
  if (params.isSimulated()) {
    pMemory = new SimulatedEnclaveMemory();
    pDevice = new MockKeystoneDevice();
  } else {
    pEMemory = new enclaveMemory();
    pDevice = new KeystoneDevice();
  }

  if (!pDevice->initDevice(params)) {
    destroy();
    return Error::DeviceInitFailure;
  }

  if (!prepareMemory(alternatePhysAddr, eappBinPath)) {
    destroy();
    return Error::DeviceError;
  }
/*
 if (!mapRuntimeBinFile(runtimeBinPath)) {
    destroy();
    return Error::VSpaceAllocationFailure;
  }
 if (!mapEappBinFile(eappBinPath)) {
    destroy();
    return Error::VSpaceAllocationFailure;
  }
*/
  if (!mapRuntime()) {
    ERROR("failed to mapRuntime()");
    destroy();
    return Error::PageAllocationFailure;
  }
  /*
 if (!loadEappBinFile(eappBinPath)) {
    ERROR("failed to loadEappBinFile()");
    destroy();
    return Error::PageAllocationFailure;
  }
  */
  if (!loadEappElfFile(eappBinPath)) {
    ERROR("failed to loadEappBinFile()");
    destroy();
    return Error::PageAllocationFailure;
  }

/* initialize stack. If not using freemem */
#ifndef USE_FREEMEM
  if (!initializeStack(DEFAULT_STACK_START, DEFAULT_STACK_SIZE, 0)) {
    ERROR("failed to init static stack");
    destroy();
    return Error::PageAllocationFailure;
  }

#endif /* USE_FREEMEM */

  uintptr_t utm_free;
  utm_free = pEMemory->allocUtm(params.getUntrustedSize());

  if (!utm_free) {
    ERROR("failed to init untrusted memory - ioctl() failed");
    destroy();
    return Error::DeviceError;
  }

  if (allocateUntrusted() != Error::Success) {
    ERROR("failed to load untrusted");
  }

  struct runtime_params_t runtimeParams;

  runtimeParams.runtime_entry = RUNTIME_ENTRY_VA;
  runtimeParams.user_entry = EAPP_ENTRY_VA;
  runtimeParams.user_size = enclaveFile->getTotalMemorySize();
  runtimeParams.untrusted_ptr =
      reinterpret_cast<uintptr_t>(params.getUntrustedMem());
  runtimeParams.untrusted_size =
      reinterpret_cast<uintptr_t>(params.getUntrustedSize());

  pEMemory->startFreeMem();

  /* TODO: This should be invoked with some other function e.g., measure() */
  if (params.isSimulated()) {
    validate_and_hash_enclave(runtimeParams);
  }

  if (pDevice->finalize(
          pEMemory->getRuntimePhysAddr(), pEMemory->getEappPhysAddr(),
          pEMemory->getFreePhysAddr(), runtimeParams) != Error::Success) {
    destroy();
    return Error::DeviceError;
  }
  if (!mapUntrusted(params.getUntrustedSize())) {
    ERROR(
        "failed to finalize enclave - cannot obtain the untrusted buffer "
        "pointer \n");
    destroy();
    return Error::DeviceMemoryMapError;
  }

  delete enclaveFile;
  enclaveFile = NULL;

  return Error::Success;
}
bool
Enclave::mapUntrusted(size_t size) {
  if (size == 0) {
    return true;
  }

  shared_buffer = pDevice->map(0, size);

  if (shared_buffer == NULL) {
    return false;
  }

  shared_buffer_size = size;

  return true;
}

Error
Enclave::destroy() {
  if (enclaveFile) {
    delete enclaveFile;
    enclaveFile = NULL;
  }

  if (runtimeFile) {
    delete runtimeFile;
    runtimeFile = NULL;
  }

  if (eappBinFile) {
    delete eappBinFile;
    eappBinFile = NULL;
  }

  return pDevice->destroy();
}

Error
Enclave::run(uintptr_t* retval) {
  if (params.isSimulated()) {
    return Error::Success;
  }

  Error ret = pDevice->run(retval);
  while (ret == Error::EdgeCallHost || ret == Error::EnclaveInterrupted) {
    /* enclave is stopped in the middle. */
    if (ret == Error::EdgeCallHost && oFuncDispatch != NULL) {
      oFuncDispatch(getSharedBuffer());
    }
    ret = pDevice->resume(retval);
  }

  if (ret != Error::Success) {
    ERROR("failed to run enclave - ioctl() failed");
    destroy();
    return Error::DeviceError;
  }

  return Error::Success;
}

void*
Enclave::getSharedBuffer() {
  return shared_buffer;
}

size_t
Enclave::getSharedBufferSize() {
  return shared_buffer_size;
}

Error
Enclave::registerOcallDispatch(OcallFunc func) {
  oFuncDispatch = func;
  return Error::Success;
}

}  // namespace Keystone
