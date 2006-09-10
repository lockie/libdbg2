

#ifndef _INTERNAL_H_
#define _INTERNAL_H_

//MSVC++ 8.0 warnings hack
#if _MSC_VER > 1310
#pragma warning (disable : 4311)
#pragma warning (disable : 4312)

#ifdef _DEBUG
#define _CRT_SECURE_NO_DEPRECATE 1
#endif 

#endif

#define WIN32_LEAN_AND_MEAN 1
#define _CRT_SECURE_NO_DEPRECATE 1
#define DBG_SOURCE 1
#include "dbg2.h"

#include <stdio.h>
#include <stdlib.h>
#include <tchar.h>
#include <time.h>

#include <tlhelp32.h>
#include <dbghelp.h>
#include <psapi.h>


// statics - to avoid using stack space
//

// TODO : Replace some of it with register vars!

static HMODULE hDll;
static HMODULE hModule;  

static HANDLE hProcess;

static char* szDumpFileName;
static HANDLE hDumpFile;

static MINIDUMP_EXCEPTION_INFORMATION ExInfo;
static MINIDUMP_USER_STREAM_INFORMATION UserStream;

#define DBG_BUFF_SIZE 4096
static char Buff[DBG_BUFF_SIZE];
//static unsigned long dwLen;

static char TempBuff[DBG_BUFF_SIZE];

static unsigned long dwTemp;
static unsigned __int64 dwTemp64;


static OSVERSIONINFOA osversion;

static MEMORYSTATUSEX memstatus;


#define DBG_HMOD_COUNT  512
#define DBG_HMOD_SIZE   (DBG_HMOD_COUNT * sizeof(HMODULE))  // max size in bytes
static HMODULE hModules[DBG_HMOD_COUNT];
static unsigned long nMods; // num of HMODULEs, not bytes !!
static unsigned long iMod;

static unsigned long len;
static unsigned long maxlen;

static MODULEINFO modinfo;

static char v[DBG_BUFF_SIZE];
static PROCESS_MEMORY_COUNTERS pmc;

static HANDLE hSnap;
static PROCESSENTRY32 proc;
static unsigned long iProc;
static HANDLE pr;

static CONTEXT cont;

static STACKFRAME stframe;

static HMODULE Module;
static char symbol[ DBG_BUFF_SIZE ]; //SYMBOL_INFO
static SYMBOL_INFO* pSym;

static IMAGEHLP_LINE line;

static unsigned long modlen;

static unsigned long address;
static unsigned long endaddr;
static unsigned char buffer[16];





// needed prototypes
//
BOOL __stdcall DllMain( HINSTANCE hinstDLL, DWORD fdwReason, LPVOID );
long __stdcall ExceptionHook( EXCEPTION_POINTERS *ExceptionInfo );





//
// internal functions
//


// inlines

// SetResult
//
long inline __fastcall SetResult(const char* Buffer, unsigned long Length) {
  if (IsBadWritePtr((void*)Buffer, Length)) {
    trace("dbg.SetResult : ERROR : bad(too small?) output string buffer!\n");
    SetLastError(ERROR_INSUFFICIENT_BUFFER);
    return 0;
  };  
  return (Buffer != Buff) ?  (lstrcpyn((char*)Buffer, Buff, ++Length)!=NULL ? Length : 0) : Length ;
};



// KByte
//
unsigned long inline __fastcall KByte(const size_t size) {  
  return (unsigned long)size / 1024;
};


void inline __fastcall SetAddress(ADDRESS& addr, const unsigned long ulAddr) {
  addr.Offset = ulAddr;   
  //addr.Segment = 0;  // ?  =(
  addr.Mode = AddrModeFlat;
};


BOOL /*inline*/ __fastcall EnumModules() {
  if (!EnumProcessModules( hProcess,
                           hModules,
                           DBG_HMOD_SIZE,
                           &dwTemp)) {
    if (dwTemp > DBG_HMOD_SIZE) trace("dbg.EnumModules : ERROR : EnumProcessModules failed because internal buffer too small!\n");
      else trace("dbg.EnumModules : ERROR : EnumProcessModules failed!\n");
    return false;
  };
    
  nMods = dwTemp / sizeof(HMODULE);

  // Get max. module name length
  maxlen = 0;  
  for (register unsigned long i = 0; i <= nMods; i++ ) {
    len = GetModuleBaseName(hProcess, hModules[i], Buff, DBG_BUFF_SIZE);
    if (len > maxlen ) maxlen = len;
    SymLoadModule(hProcess, NULL, NULL, Buff, (DWORD)hModules[i], 0);
  };
  maxlen++;

  return true;
};


/*

// GetModuleVersion
//
unsigned long __fastcall  GetModuleVersion(const char* szFileName, const char* buff) {

  dwTemp = GetFileVersionInfoSize((char*)szFileName, &dwTemp);    
  if (dwTemp==0) {
    trace("dbg.GetModuleVersion : WARNING : GetFileVersionInfoSize failed!\n");
    return 0;
  };

  if (DBG_BUFF_SIZE < dwTemp) {
    trace("dbg.GetModuleVersion : ERROR : internal buffer too small!");
    return 0;
  };

//  v = HeapAlloc(GetProcessHeap(), 0, dwTemp);

  if (!GetFileVersionInfoA((char*)szFileName, NULL, dwTemp, v)) {
    trace("dbg.GetModuleVersion : ERROR : GetFileVersionInfoA failed!\n");
    return 0;
  };
  if (!VerQueryValueA(v, "\\", (void**)&ver, (unsigned int*)&dwTemp ) ) {
    trace("dbg.GetModuleVersion : ERROR : VerQueryValueA failed!\n");
    return 0;
  };    
      
  sprintf((char*)buff, "version %lu.%lu.%lu.%lu", HIWORD(ver->dwFileVersionMS), 
    LOWORD(ver->dwFileVersionMS), HIWORD(ver->dwFileVersionLS), LOWORD(ver->dwFileVersionLS) );   

  return sprintf((char*)buff, "%-24.24s", buff);  // прикольно, блин.
};

*/

// GetLoadedModule
//
DWORD __fastcall /*__stdcall*/ GetLoadedModule() {
  
  // TODO : use CreateToolHelp32Snapshot / Module32First / Module32Next !?!??

  register DWORD dwLen = sprintf(Buff, "Module #%03lu : ", iMod);

  dwTemp = GetModuleBaseName(hProcess, hModules[iMod], TempBuff, DBG_BUFF_SIZE );
  if (dwTemp == 0) {
    trace("dbg.GetLoadedModule : ERROR : GetModuleBaseName failed!\n");
    return 0;
  };
  //strcpy(&Buff[dwLen], TempBuff);
  FillMemory(&Buff[dwLen] + sprintf(&Buff[dwLen], "%s", TempBuff), maxlen+2, 0x20); //#32
  dwLen+=(maxlen+1);
  
  if (!GetModuleInformation(hProcess, hModules[iMod], 
   &modinfo, sizeof(MODULEINFO)) ) {
    trace("dbg.GetLoadedModule : ERROR : GetModuleInformation failed!\n");
    return 0;
  };
  
  dwLen += sprintf(&Buff[dwLen], "%#08p - %#08x, entrypoint at %#08p, ", modinfo.lpBaseOfDll, 
    (unsigned long)modinfo.lpBaseOfDll + modinfo.SizeOfImage, modinfo.EntryPoint);

  dwTemp = GetTimestampForLoadedLibrary(hModules[iMod]);
  if (dwTemp == 0) {
    trace("dbg.GetLoadedModule : ERROR : GetTimestampForLoadedLibrary failed!\n");
    return 0;
  };
  
  tm Tm;
  _localtime32_s(&Tm, (__time32_t*)&dwTemp); //f*ck!
  dwLen+=(DWORD)strftime(&Buff[dwLen], DBG_BUFF_SIZE-dwLen, "timestamp %c, ", &Tm);

  if ( GetModuleFileNameEx(hProcess, hModules[iMod], TempBuff, DBG_BUFF_SIZE ) == 0 ) {
    trace("dbg.GetLoadedModule : ERROR : GetModuleFileNameEx failed!\n");
    return 0;
  };
  
//  dwTemp = GetFileVersion(TempBuff, &Buff[dwLen]);
  if (dwTemp == 0) {
    dwLen+=sprintf( &Buff[dwLen], "%-24.24s", _T("version <Unknown>") );
  }
  dwLen+=dwTemp;

  dwLen += sprintf(&Buff[dwLen], "; %s", TempBuff);

  return dwLen;
};



// GetPriority
//
inline const char* __fastcall GetPriority(const unsigned long p) {
  switch (p) {
    case 24  :        
    case 23  :  
    case 22  :
    case 21  :
    case 20  :
    case 19  :
    case 18  :
    case 17  :
    case 16  :
    case 15  :
    case 14  :
      return _T("realtime    ");

    case 13  :  
    case 12  :
      return _T("high        ");    

    case 11 :
    case 10 :
      return _T("above normal");
    
    case 9  :
    case 8  :
      return _T("normal      ");

    case 7  :
    case 6  :
      return _T("below normal");

    case 5  :
    case 4  :
      return _T("low         ");

    case 3  :
    case 2  :
    case 1  :
    case 0  :
      return _T("idle        ");

    default :
      return _T("<unknown>   ");
  };
};


// GetProcess
//
DWORD __fastcall /*__stdcall*/ GetProcess() {

/*  if (proc.th32ProcessID!=0) {
    dwTemp = (DWORD)OpenProcess(PROCESS_QUERY_INFORMATION, false, proc.th32ProcessID);
    if (dwTemp==NULL) {
      trace("dbg.GetProcess : ERROR : OpenProcess failed!\n");
      return 0;
    };
    if (!GetProcessMemoryInfo( (HANDLE)dwTemp , &pmc, sizeof(pmc) ) ) {
      trace("dbg.GetProcess : ERROR : GetProcessMemoryInfo failed!\n");
      return 0;
    };
   } else {
    pmc.WorkingSetSize = 0;
  };
  //pmc.PageFaultCount // -??  
*/

  register DWORD dwLen = sprintf(Buff,"Process #%03lu : ID %03x, %3d thread(s), priotity %s; %s", 
    iProc, proc.th32ProcessID, proc.cntThreads, GetPriority(proc.pcPriClassBase), proc.szExeFile  );
  
  //register DWORD b = SetResult(Buffer);  
  //if (b) iProc++;
  //return b;
  return dwLen;
};



//   Это не функция, а кошмар.
//                           Бьерн Страуструп.
//

// GetExceptionText
//
const char* __fastcall /*__stdcall*/ GetExceptionText(unsigned long code) {
  switch ( code ) {
    case EXCEPTION_ACCESS_VIOLATION         :
      return ( _T ( "EXCEPTION_ACCESS_VIOLATION" ) ) ;

    case EXCEPTION_STACK_OVERFLOW           :
      return ( _T ( "EXCEPTION_STACK_OVERFLOW" ) ) ;

    case EXCEPTION_DATATYPE_MISALIGNMENT    :
      return ( _T ( "EXCEPTION_DATATYPE_MISALIGNMENT" ) ) ;

    case EXCEPTION_BREAKPOINT               :
      return ( _T ( "EXCEPTION_BREAKPOINT" ) ) ;

    case EXCEPTION_SINGLE_STEP              :
      return ( _T ( "EXCEPTION_SINGLE_STEP" ) ) ;

    case EXCEPTION_ARRAY_BOUNDS_EXCEEDED    :
      return ( _T ( "EXCEPTION_ARRAY_BOUNDS_EXCEEDED" ) ) ;

    case EXCEPTION_FLT_DENORMAL_OPERAND     :
      return ( _T ( "EXCEPTION_FLT_DENORMAL_OPERAND" ) ) ;

    case EXCEPTION_FLT_DIVIDE_BY_ZERO       :
      return ( _T ( "EXCEPTION_FLT_DIVIDE_BY_ZERO" ) ) ;

    case EXCEPTION_FLT_INEXACT_RESULT       :
      return ( _T ( "EXCEPTION_FLT_INEXACT_RESULT" ) ) ;

    case EXCEPTION_FLT_INVALID_OPERATION    :
      return ( _T ( "EXCEPTION_FLT_INVALID_OPERATION" ) ) ;

    case EXCEPTION_FLT_OVERFLOW             :
      return ( _T ( "EXCEPTION_FLT_OVERFLOW" ) ) ;

    case EXCEPTION_FLT_STACK_CHECK          :
      return ( _T ( "EXCEPTION_FLT_STACK_CHECK" ) ) ;

    case EXCEPTION_FLT_UNDERFLOW            :
      return ( _T ( "EXCEPTION_FLT_UNDERFLOW" ) ) ;

    case EXCEPTION_INT_DIVIDE_BY_ZERO       :
      return ( _T ( "EXCEPTION_INT_DIVIDE_BY_ZERO" ) ) ;

    case EXCEPTION_INT_OVERFLOW             :
      return ( _T ( "EXCEPTION_INT_OVERFLOW" ) ) ;

    case EXCEPTION_PRIV_INSTRUCTION         :
      return ( _T ( "EXCEPTION_PRIV_INSTRUCTION" ) ) ;

    case EXCEPTION_IN_PAGE_ERROR            :
      return ( _T ( "EXCEPTION_IN_PAGE_ERROR" ) ) ;

    case EXCEPTION_ILLEGAL_INSTRUCTION      :
      return ( _T ( "EXCEPTION_ILLEGAL_INSTRUCTION" ) ) ;

    case EXCEPTION_NONCONTINUABLE_EXCEPTION :
      return ( _T ( "EXCEPTION_NONCONTINUABLE_EXCEPTION" ) ) ;

    case EXCEPTION_INVALID_DISPOSITION      :
      return ( _T ( "EXCEPTION_INVALID_DISPOSITION" ) ) ;

    case EXCEPTION_GUARD_PAGE               :
      return ( _T ( "EXCEPTION_GUARD_PAGE" ) ) ;

    case EXCEPTION_INVALID_HANDLE           :
      return ( _T ( "EXCEPTION_INVALID_HANDLE" ) ) ;

    default :
      return ( NULL ) ;
    };
};


#endif  // _INTERNAL_H_