
#define _CRT_SECURE_NO_DEPRECATE

#include <stdio.h>
#include <conio.h>

#include "dbg2.h"

static VS_FIXEDFILEINFO* verinfo;

// main
//
int main() {
  
  assert(InitDbg(NULL));

  printf("main() : Enter\n");
  
  if( !assert( DbgGetFileVersion("dbg2.dll", &verinfo) ) ) {
    printf("Unable to get version of dbg2, exiting...\n");  
    _getch();
    return 0;
  };

  printf("dbg2 version = %u.%u.%u.%u\n", HIWORD(verinfo->dwFileVersionMS), 
    LOWORD(verinfo->dwFileVersionMS), HIWORD(verinfo->dwFileVersionLS), LOWORD(verinfo->dwFileVersionLS) );
  _getch();

  printf("Writing dump...");
  assert(DbgWriteDump(GetCurrentProcess(), GetCurrentProcessId(), GetCurrentThreadId(), NULL, NULL, NULL));

  long* p = NULL;

  trace("p=%p", p);

  SetLastError(6);

  assert(!"Gonna crash");
  
  if(!SUPERASSERT(p!=NULL)) {
    trace("oops...");    
  };

  __try {
    *p = 0;

    } __except( assert(DbgWriteDump(GetCurrentProcess(), GetCurrentProcessId(), GetCurrentThreadId(), NULL, GetExceptionInformation(), NULL)) ) {
      // None =) 
    };

  return 0;
};