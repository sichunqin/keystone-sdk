//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#pragma once

#include <assert.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stddef.h>
#include <sys/types.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <functional>
#include <iostream>

#include "./common.h"
extern "C" {
#include "common/sha3.h"
}
#include "ElfFile.hpp"
#include "Error.hpp"
#include "KeystoneDevice.hpp"
#include "Memory.hpp"
#include "Params.hpp"
#include "enclaveMemory.hpp"
#include "binFile.hpp"

namespace Keystone {

typedef std::function<void(void*)> OcallFunc;

class Enclave {
 private:
  Params params;
  ElfFile* runtimeFile;
  ElfFile* enclaveFile;
  binFile* runtimeBinFile;
  binFile* eappBinFile;
  Memory* pMemory;
  enclaveMemory* pEMemory;
  KeystoneDevice* pDevice;
  char hash[MDSIZE];
  hash_ctx_t hash_ctx;
  uintptr_t runtime_stk_sz;
  void* shared_buffer;
  size_t shared_buffer_size;
  OcallFunc oFuncDispatch;
  size_t eappbinSize;
  bool mapUntrusted(size_t size);
  bool allocPage(uintptr_t va, uintptr_t src, unsigned int mode);
  bool initStack(uintptr_t start, size_t size, bool is_rt);
  bool initializeStack(uintptr_t start, size_t size, bool is_rt);
  Error loadUntrusted();
  Error allocateUntrusted();
  bool mapElf(ElfFile* file);
  Error loadElf(ElfFile* file);
  Error validate_and_hash_enclave(struct runtime_params_t args);

  bool initFiles(const char*, const char*);
  bool initDevice();
  bool prepareEnclave(uintptr_t alternatePhysAddr);
  bool prepareMemory(uintptr_t alternatePhysAddr, const char *eappbinPath);

  bool mapRuntime();
  bool mapEappBinFile(const char* path);
  bool loadEappElfFile(const char* path);
  bool loadEappBinFile(const char* path);
  bool mapRuntimeBinFile(const char* path);
  bool initMemory();

 public:
  Enclave();
  ~Enclave();
  const char* getHash();
  void* getSharedBuffer();
  size_t getSharedBufferSize();
  Error registerOcallDispatch(OcallFunc func);
  Error init(const char* filepath, Params parameters);
  Error init(const char* filepath, const char* runtime, Params parameters);
  Error init(
      const char* eapppath, const char* runtimepath, Params _params,
      uintptr_t alternatePhysAddr);

  Error initialize(
      const char* eappBinPath, const char* runtimeBinPath, Params _params, uintptr_t alternatePhysAdd);
  Error initialize(
      const char* eappBinPath, Params _params);
  Error destroy();
  Error run(uintptr_t* ret = nullptr);
};

uint64_t
calculate_required_pages(
    uint64_t eapp_sz, uint64_t eapp_stack_sz, uint64_t rt_sz,
    uint64_t rt_stack_sz);

}  // namespace Keystone
