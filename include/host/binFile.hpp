//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#pragma once

#include <fcntl.h>
#include <unistd.h>
#include <iostream>
#include <string>
#include "./common.h"
#include "./keystone_user.h"



namespace Keystone {

class binFile {
 public:
  explicit binFile(std::string filename);
  ~binFile();
  size_t getFileSize() { return fileSize; }
  bool isValid();
  void* getPtr();

 private:
  int filep;

  /* virtual addresses */
  uintptr_t minVaddr;
  uintptr_t maxVaddr;

  void* ptr;
  size_t fileSize;

};

}  // namespace Keystone
