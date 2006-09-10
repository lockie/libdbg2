//         Совершенство достижимо только в момент краха.
//                                                       С.Н. Паркинсон.
//



#include "internal.h"
#include "dbg_assert.h"

// TODO : Optimize!!  especially GetLoadedModule!


// DllMain
//
BOOL __stdcall DllMain( HINSTANCE hinstDLL, DWORD fdwReason, LPVOID ) {

  switch (fdwReason) {
    case DLL_PROCESS_ATTACH :
	    DisableThreadLibraryCalls(hDll = hinstDLL);            
      hModule = GetModuleHandle(NULL);
      hProcess = GetCurrentProcess();
      SetReportMode(RM_DEFAULT);
      SetUnhandledExceptionFilter(ExceptionHook);
      break;

    case DLL_PROCESS_DETACH :
      // cleanup code
      SetUnhandledExceptionFilter(NULL);      
      SymCleanup(hProcess);
      if (hOutFile!=INVALID_HANDLE_VALUE) {
        CloseHandle(hOutFile);
        hOutFile = INVALID_HANDLE_VALUE;
      };
      hModule = NULL;
      hProcess = NULL;
      break;
  };

  return true;
};


// InitDbg
//
BOOL __stdcall InitDbg(const char* SymsPath, LPTOP_LEVEL_EXCEPTION_FILTER ExceptionFilter ) {
  SymSetOptions(SymGetOptions() | (SYMOPT_CASE_INSENSITIVE | SYMOPT_UNDNAME | 
    SYMOPT_DEFERRED_LOADS | SYMOPT_LOAD_LINES) );
  if (!SymInitialize(hProcess, (char*)SymsPath, true)) {
    trace("dbg.InitDbg : ERROR : SymInitialize failed!\n");
    return false;
  };

  UserFilter = ExceptionFilter;

  return true;
};



long __stdcall ExceptionHook( EXCEPTION_POINTERS* ExceptionInfo ) {

  if ( (IsBadReadPtr(ExceptionInfo, sizeof(EXCEPTION_POINTERS) ) ) ||
    (IsBadReadPtr(ExceptionInfo->ExceptionRecord, sizeof(EXCEPTION_RECORD) ) )  ||
     (IsBadReadPtr(ExceptionInfo->ContextRecord, sizeof(CONTEXT)) ) ) {
    trace("dbg.ExceptionHook : ERROR : Bad EXCEPTION_POINTERS!\n");
    return EXCEPTION_EXECUTE_HANDLER;
  };

  if ( ExceptionInfo->ExceptionRecord->ExceptionCode == 
      EXCEPTION_STACK_OVERFLOW ) {
    trace ( "dbg.ExceptionHook : WARNING : EXCEPTION_STACK_OVERFLOW occurred!\n" ) ;
  };

  __try {
    if (IsBadCodePtr((FARPROC)UserFilter)) {
      if (!GetFaultReason(*ExceptionInfo, TempBuff)) {
        trace("dbg.ExceptionHook : ERROR : UserFilter unavivable, and GetFaultReason failed!\n");
       } else {
        OutputDebugString(TempBuff);
        OutputDebugString("\n");
      };
      return EXCEPTION_EXECUTE_HANDLER;
     } else {
      // call user's filter    
      dwTemp = UserFilter(ExceptionInfo);
      if (dwTemp!=1 && dwTemp!=-1 && dwTemp!=0) return EXCEPTION_EXECUTE_HANDLER;
        else return dwTemp;
    };
  }
  __except (EXCEPTION_EXECUTE_HANDLER) {
    trace("dbg.ExceptionHook : crashed itself!");
    return EXCEPTION_EXECUTE_HANDLER;
  };
};




// GetFaultReason
//
DWORD __stdcall GetFaultReason(const EXCEPTION_POINTERS ExceptionInfo, const char* Buffer) {
  
  dwLen = GetModuleBaseNameA(hProcess, NULL, Buff, DBG_BUFF_SIZE);
  if (dwLen == 0) {
    trace("dbg.GetFaultReason : ERROR : GetModuleBaseNameA failed!\n");
    return 0;
  };

  dwLen += wsprintf(&Buff[dwLen], " caused an ");

  // TODO : в таких местах dwTemp можно заменить на временную
  // регистровую переменную для большего быстродействия.
  dwTemp = (long)GetExceptionText(ExceptionInfo.ExceptionRecord->ExceptionCode);
  if (dwTemp != NULL) {;
    dwLen += wsprintf(&Buff[dwLen], "%s", dwTemp);
   } else {
    // TODO : Test it !!!
    dwTemp = (
      FormatMessage( FORMAT_MESSAGE_IGNORE_INSERTS |
                     FORMAT_MESSAGE_FROM_SYSTEM,
                     //GetModuleHandle (_T("NTDLL.DLL")) ,
                     NULL,
                     ExceptionInfo.ExceptionRecord->ExceptionCode,
                     0                                 ,
                     &Buff[dwLen],
                     DBG_BUFF_SIZE - dwLen,
                     0         ) * sizeof ( TCHAR ) );

    if ( dwTemp == 0 ) {
      dwLen+=wsprintf(&Buff[dwLen], "<Unknown exception>" );
     } else {
      dwLen+=(dwTemp - 3 * sizeof(TCHAR) ) ;  // #46#13#10 - 3 chars
    };
  };

  dwLen += wsprintf(&Buff[dwLen], " in module ");

  dwTemp = SymGetModuleBase(hProcess, (long)ExceptionInfo.ExceptionRecord->ExceptionAddress );

  if (dwTemp == 0) {
    dwLen+=wsprintf(&Buff[dwLen], "<Unknown module>");
   } else {
    dwLen+=GetModuleBaseName( hProcess,
                              (HMODULE)dwTemp,          // выглядит мразматично, но почему-то работает...
                              &Buff[dwLen],
                              DBG_BUFF_SIZE - dwLen );
  };

  dwLen += wsprintf(&Buff[dwLen], " at %04x:%08x", 
    ExceptionInfo.ContextRecord->SegCs , ExceptionInfo.ExceptionRecord->ExceptionAddress );

  return SetResult(Buffer);
};


// GetSystemInfo
//
DWORD __stdcall GetSysInfo(const char* Buffer) {

  // get windows version
  osversion.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
  if (!GetVersionExA(&osversion)) {
    trace("dbg.GetSysInfo : ERROR : GetVersionExA failed!");
    return 0;
  };
  switch (osversion.dwPlatformId) {
    case VER_PLATFORM_WIN32s :
      // Windows 3.1  (???)  =(
      dwLen = wsprintf(Buff, "System is Windows 3.1");
    case VER_PLATFORM_WIN32_WINDOWS :
      if (osversion.dwMinorVersion == 0) {
        // Windows 95
        dwLen = wsprintf(Buff, "System is Windows 95 build %hu  %s", LOWORD(osversion.dwBuildNumber), osversion.szCSDVersion );
       } else {
        // Windows 98
        dwLen = wsprintf(Buff, "System is Windows 98 build %hu  %s", LOWORD(osversion.dwBuildNumber), osversion.szCSDVersion );
      };
    case VER_PLATFORM_WIN32_NT :
      dwLen = wsprintf(Buff, "System is Windows NT %lu.%lu build %u  %s", osversion.dwMajorVersion, osversion.dwMinorVersion, 
        osversion.dwBuildNumber, osversion.szCSDVersion );
  };
  
  // get computer name
  dwLen += wsprintf(&Buff[dwLen], "\nComputer name is ");
  dwTemp = (DBG_BUFF_SIZE - dwLen) / sizeof(TCHAR);
  if (!GetComputerNameA(&Buff[dwLen], &dwTemp)) {
    trace("dbg.GetSysInfo : ERROR : GetComputerNameA failed!\n");   
    return 0;
  };
  dwLen += dwTemp;
  
  // get user name
  dwLen += wsprintf(&Buff[dwLen], "\nUser name is ");
  dwTemp = (DBG_BUFF_SIZE - dwLen) / sizeof(TCHAR);
  if (!GetUserNameA(&Buff[dwLen], &dwTemp)) {
    trace("dbg.GetSysInfo : ERROR : GetUserNameA failed!");    
    return 0;
  };
  dwLen += (dwTemp-1); 
  
  memstatus.dwLength = sizeof(memstatus);
  if (!GlobalMemoryStatusEx(&memstatus)) {
    trace("dbg.GetSysInfo : ERROR : GlobalMemoryStatusEx failed!\n");
    return 0;
  };
  dwLen+=wsprintf(&Buff[dwLen], "\nTotal physical memory %luK\nPageFile size %luK\nMemory load %lu%s\nAvailable memory %luK", 
    KByte((DWORD)memstatus.ullTotalPhys), KByte((DWORD)memstatus.ullAvailPageFile ), memstatus.dwMemoryLoad, _T("%"), KByte((DWORD)memstatus.ullAvailVirtual)   );  
  
  return SetResult(Buffer);
};

// GetFirstLoadedModule
//
DWORD __stdcall GetFirstLoadedModule(const char* Buffer) {

  if (!EnumModules()) return 0;

  iMod = 0;

  if (GetLoadedModule()) {
    iMod = 1;
    return SetResult(Buffer);
  } else return 0;  
};


// GetNextLoadedModule
//
DWORD __stdcall GetNextLoadedModule(const char* Buffer) {

  if (iMod >= nMods) {
    SetLastError(ERROR_NO_MORE_FILES);
    nMods = 0; // хе-хе!
    return 0;
  };  

  if (GetLoadedModule()) {
    iMod++;
    return SetResult(Buffer);
  } else return 0;  
};



// GetProcessInfo
//
DWORD __stdcall GetProcessInfo(const char* Buffer) {

  if (!GetProcessMemoryInfo(hProcess, &pmc, sizeof(pmc) ) ) {
    trace("dbg.GetProcessInfo : ERROR : GetProcessMemoryInfo failed!\n");
    return 0;
  };

  dwLen+=wsprintf(Buff, "Process ID %lu\nCommand line ""%s""\nPage faults count %lu\nPeak working set size %luK\nCurrent working set size %luK\nPeak paged pool usage %luK\nPeak nonpaged pool usage %luK\nPeak pagefile usage %luK\n" ,    
    GetCurrentProcessId(), GetCommandLine(), pmc.PageFaultCount, KByte(pmc.PeakWorkingSetSize), KByte(pmc.WorkingSetSize), 
    KByte(pmc.QuotaPeakPagedPoolUsage), KByte(pmc.QuotaPeakNonPagedPoolUsage), KByte(pmc.PeakPagefileUsage)  );

  return SetResult(Buffer);
};


// GetFirstSystemProcess
//
DWORD __stdcall GetFirstSystemProcess(const char* Buffer) {

  hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
  if ( hSnap == INVALID_HANDLE_VALUE ) {
    trace("dbg.GetFirstSystemProcess : ERROR : CreateToolhelp32Snapshot failed!\n");
    return 0;
  };
  
  proc.dwSize = sizeof(proc);
  if (!Process32First(hSnap, &proc)) {
    trace("dbg.GetFirstSystemProcess : ERROR : Process32First failed!\n");
    return 0;
  };
  
  iProc = 0;

  if (GetProcess()) {
    iProc = 1;
    return SetResult(Buffer);
  } else return 0;   
};

// GetNextSystemProcess
//
DWORD __stdcall GetNextSystemProcess(const char* Buffer) {
 
  if (!Process32Next(hSnap, &proc)) {
    if (GetLastError()!=ERROR_NO_MORE_FILES) trace("dbg.GetNextSystemProcess : ERROR : Process32Next failed!\n");            
    CloseHandle(hSnap);
    hSnap = NULL;
    return 0;
  };

  if (GetProcess()) {
    iProc++;
    return SetResult(Buffer);
  } else return 0;   
};


//
// TODO later : advanced info about all threads !!!
//


// GetRegisters
//
DWORD __stdcall GetRegisters(const EXCEPTION_POINTERS ExceptionInfo, const char* Buffer) {

  dwLen = wsprintf(Buff, "eax = %#08x ebx = %#08x ecx = %#08x edx = %#08x esi = %#08x edi = %#08x\n",  ExceptionInfo.ContextRecord->Eax, 
    ExceptionInfo.ContextRecord->Ebx, ExceptionInfo.ContextRecord->Ecx, ExceptionInfo.ContextRecord->Edx, ExceptionInfo.ContextRecord->Esi, ExceptionInfo.ContextRecord->Edi );

  dwLen +=wsprintf(&Buff[dwLen], "ebp = %#08x esp = %#08x eip = %#08x flg = %#08x cs = %#04x      ss = %#04x", ExceptionInfo.ContextRecord->Ebp, 
    ExceptionInfo.ContextRecord->Esp, ExceptionInfo.ContextRecord->Eip, ExceptionInfo.ContextRecord->EFlags, ExceptionInfo.ContextRecord->SegCs, ExceptionInfo.ContextRecord->SegSs);

  return SetResult(Buffer);  
};


// GetFirstStackTrace
//
DWORD __stdcall GetFirstStackTrace(const EXCEPTION_POINTERS ExceptionInfo, const char* Buffer) {
  
  if (!EnumModules()) return 0; // to get maxlen  
  
  ZeroMemory(&stframe, sizeof(stframe));
  SetAddress(stframe.AddrPC,     ExceptionInfo.ContextRecord->Eip);
  SetAddress(stframe.AddrFrame,  ExceptionInfo.ContextRecord->Ebp);
  SetAddress(stframe.AddrStack,  ExceptionInfo.ContextRecord->Esp);
  //SetAddress(stframe.AddrReturn, 0);
  //SetAddress(stframe.AddrBStore, 0);
  
  memcpy(&cont, ExceptionInfo.ContextRecord, sizeof(CONTEXT));

  dwLen = wsprintf(Buff, "address    logical addr  frame      param#1    param#2    param#3    param#4    module ");

  memset(&Buff[dwLen], 0x20, (modlen = (maxlen < 6) ? 0 : maxlen - 6) );
  dwLen+=modlen;
  dwLen+=wsprintf(&Buff[dwLen], "func                                    location");

  return SetResult(Buffer);
};

// GetNextStackTrace
//
DWORD __stdcall GetNextStackTrace(const char* Buffer) {

  if (!StackWalk(IMAGE_FILE_MACHINE_I386,
                 hProcess,
                 GetCurrentThread(),
                 &stframe,
                 &cont,
                 (PREAD_PROCESS_MEMORY_ROUTINE)
                   ReadProcessMemory,
                 SymFunctionTableAccess,
                 SymGetModuleBase,
                 NULL) ) return 0;

  // check that returned correct data.

  /*  if (GetLastError()!=NO_ERROR) {
    trace("dbg.GetNextStackTrace : ERROR : StackWalk failed!\n");
    return 0;
    // невыносимая жестокость =)
  };  */

  if (stframe.AddrFrame.Offset == 0) return 0;
  Module = (HMODULE)SymGetModuleBase(hProcess, stframe.AddrPC.Offset);  // module handle - маразм #2.
  if ( Module == 0) {
    trace("dbg.GetNextStackTrace : ERROR : StackWalk returned wrong function address!\n");
    return 0;
  };

  dwLen = wsprintf(Buff, "%#08x %04x:%08x %#08x %#08x %#08x %#08x %#08x ", stframe.AddrPC.Offset, cont.SegCs,
    stframe.AddrPC.Offset - (DWORD)Module, stframe.AddrFrame.Offset, stframe.Params[0], stframe.Params[1], stframe.Params[2], stframe.Params[3] );

  dwTemp = GetModuleBaseName(hProcess, Module, &Buff[dwLen], DBG_BUFF_SIZE - dwLen);
  if (dwTemp == 0) {
    trace("dbg.GetNextStackTrace : ERROR : GetModuleBaseName failed!");
    return 0;
  };
  memset(&Buff[dwLen+dwTemp], 0x20, maxlen - dwTemp );
  dwLen+=maxlen;

  pSym = (PSYMBOL_INFO)&symbol;
  ZeroMemory(pSym, DBG_BUFF_SIZE);
  pSym->SizeOfStruct = sizeof(SYMBOL_INFO);
  pSym->MaxNameLen = DBG_BUFF_SIZE - sizeof(SYMBOL_INFO);
  
  if (!SymFromAddr(GetCurrentProcess(), stframe.AddrPC.Offset, &dwTemp64, pSym)) {
    dwLen+=wsprintf(&Buff[dwLen], " <Unknown function>              ");
   } else {
    register long l;
    if (dwTemp64 == 0) {
      l = wsprintf(&Buff[dwLen], " %s()", pSym->Name);      
     } else {
      l = wsprintf(&Buff[dwLen], " %s() + %d byte(s)", pSym->Name, dwTemp64);
    };
    dwLen+=l;

    // line info
    line.SizeOfStruct = sizeof(line);  
    if (SymGetLineFromAddr(hProcess, stframe.AddrPC.Offset, &dwTemp, &line)) {
      l = (40-l)>0 ? 40-l : 1;
      memset(&Buff[dwLen], 0x20, l);
      dwLen+=l;
      dwLen+=wsprintf(&Buff[dwLen], " %s, line %d", line.FileName, line.LineNumber );
    };
  };

  return SetResult(Buffer);
};


// GetMemoryDump
//
DWORD __stdcall GetMemoryDump(const void* Addr, const size_t Size, const char* Buffer) {

  address = (DWORD)Addr - (DWORD)Addr % 16;
  endaddr = (DWORD)Addr+Size+(DWORD)Addr % 16;
  dwLen = 0;

  do {
    dwLen += wsprintf(&Buff[dwLen], "%#08x: ", address);
    if(!ReadProcessMemory(hProcess, (void*)address, &buffer[0], 16, &dwTemp)) {
      dwLen+=wsprintf(&Buff[dwLen], "?? ?? ?? ?? ?? ?? ?? ??  ?? ?? ?? ?? ?? ?? ?? ??  ................\n");
     } else {
      dwLen += wsprintf(&Buff[dwLen], "%02x %02x %02x %02x %02x %02x %02x %02x  %02x %02x %02x %02x %02x %02x %02x %02x  ", 
        buffer[0], buffer[1], buffer[2], buffer[3], buffer[4], buffer[5], buffer[6], buffer[7], 
        buffer[8], buffer[9], buffer[10], buffer[11], buffer[12], buffer[13], buffer[14], buffer[15]); 

      for (register DWORD i=0; i<16; i++) {
        if (buffer[i]<0x20) buffer[i] = 0x2e; // "."
      };
      dwLen += wsprintf(&Buff[dwLen], "%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c\n",
        buffer[0], buffer[1], buffer[2], buffer[3], buffer[4], buffer[5], buffer[6], buffer[7], 
        buffer[8], buffer[9], buffer[10], buffer[11], buffer[12], buffer[13], buffer[14], buffer[15]);
    };

    address+=16;
  } while (address < endaddr && dwLen < DBG_BUFF_SIZE - 79);

  return SetResult(Buffer);
};

// GetCodeDump
//
DWORD __stdcall GetCodeDump(const EXCEPTION_POINTERS ExceptionInfo, const char* Buffer) {
  return GetMemoryDump((void*)((DWORD)ExceptionInfo.ExceptionRecord->ExceptionAddress-16), 64, Buffer);
};

// GetStackDump
//
DWORD __stdcall GetStackDump(const EXCEPTION_POINTERS ExceptionInfo, const char* Buffer) {
  return GetMemoryDump((void*)(ExceptionInfo.ContextRecord->Esp-16), 512, Buffer);
};

