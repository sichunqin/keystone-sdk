//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#include "eapp_utils.h"
#include "string.h"
#include "edge_call.h"
#include <syscall.h>

#define OCALL_PRINT_STRING 1

unsigned long ocall_print_string(char* string);
extern unsigned char * bss_start;
extern unsigned char * bss_end;
int main(){
  INIT();
  memset(bss_start, 0, bss_end - bss_start + 1);
  ocall_print_string("Hello World");

  EAPP_RETURN(0);
}

unsigned long ocall_print_string(char* string){
  unsigned long retval;
  ocall(OCALL_PRINT_STRING, string, strlen(string)+1, &retval ,sizeof(unsigned long));
  return retval;
}
