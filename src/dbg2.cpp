//         Совершенство достижимо только в момент краха.
//                                                       С.Н. Паркинсон.
//


#include "internal.h"
#include "dbg_assert.h"


// DllMain
//
BOOL __stdcall DllMain( HINSTANCE hinstDLL, DWORD fdwReason, LPVOID ) {
  switch (fdwReason) {
    case DLL_PROCESS_ATTACH :     
      API_VERSION v;
      v.MajorVersion = 6;
      v.MinorVersion = 1;
      v.Revision = 0;
      ImagehlpApiVersionEx(&v); // we need at least 6.1
      SetUnhandledExceptionFilter(ExceptionHook);	    
      DisableThreadLibraryCalls(hDll = hinstDLL);      
      DbgSetReportMode(DBG_INFO,   DBG_MODE_ODS);
      DbgSetReportMode(DBG_WARN,   DBG_MODE_ODS | DBG_MODE_STDERR);
      DbgSetReportMode(DBG_ASSERT, DBG_MODE_ODS | DBG_MODE_STDERR | DBG_MODE_MSGBOX);
      break;
    case DLL_PROCESS_DETACH :
      // cleanup code
      SetUnhandledExceptionFilter(NULL);      
      SymCleanup(GetCurrentProcess());
      break;
  };
  return true;
};


// InitDbg
//
BOOL __stdcall InitDbg( const char* szSymsPath, const char* szDumpFilename ) {
  SymSetOptions(SymGetOptions() | (SYMOPT_CASE_INSENSITIVE | SYMOPT_UNDNAME | 
    SYMOPT_DEFERRED_LOADS | SYMOPT_LOAD_LINES) );
  if (!SymInitialize(GetCurrentProcess(), (char*)szSymsPath, true)) {
    trace("dbg.InitDbg : ERROR : SymInitialize failed!\n");
    return false;
  };
  szDumpFileName = (szDumpFilename) ? szDumpFilename : "dump.dmp" ;
  return true;
};


// ExceptionHook
//
long __stdcall ExceptionHook( EXCEPTION_POINTERS* ExceptionInfo ) {

  if ( ExceptionInfo->ExceptionRecord->ExceptionCode == 
      EXCEPTION_STACK_OVERFLOW ) {
    trace ( "dbg.ExceptionHook : WARNING : EXCEPTION_STACK_OVERFLOW occurred!\n" ) ;
  };
  __try {
    // write dump...
    DbgWriteDump(GetCurrentProcess(), GetCurrentProcessId(), GetCurrentThreadId(), NULL, ExceptionInfo, NULL);
    return EXCEPTION_EXECUTE_HANDLER;
  }
  __except (EXCEPTION_EXECUTE_HANDLER) {
    trace("dbg.ExceptionHook : crashed itself!");
    return EXCEPTION_EXECUTE_HANDLER;
  };
};


// GetFirstStackTrace
//
DWORD __stdcall GetFirstStackTrace(DWORD /*dwOpts*/, HANDLE /*hProcess*/, CONTEXT /*ContextRecord*/, char* Buffer) {  
  register DWORD dwLen = 0;
  

  // TODO : TODO !!


  return SetResult(Buffer, dwLen);  
};


// GetFileVersion
// 
DWORD __stdcall DbgGetFileVersion(const char* szFileName, VS_FIXEDFILEINFO** Version ) {
  // first, check the buffer
  if(!assert(Version)) {
    SetLastError(ERROR_INVALID_PARAMETER);
    return 0;
  };
  if( !assert(!IsBadWritePtr(Version, sizeof(VS_FIXEDFILEINFO))) ) {
    SetLastError(ERROR_INVALID_PARAMETER);
    return 0;    
  };

  // size of version info...
  DWORD dwRet = GetFileVersionInfoSize((char*)szFileName, &dwTemp);    
  if (dwRet==0) {
    trace("dbg.GetFileVersion : WARNING : GetFileVersionInfoSize failed!\n");   
    return 0;
  };
  if (DBG_BUFF_SIZE < dwRet) {
    trace("dbg.GetFileVersion : ERROR : internal buffer too small!");
    return 0;
  };

  // Get It !
  if (!GetFileVersionInfoA((char*)szFileName, NULL, dwRet, v)) {
    trace("dbg.GetFileVersion : ERROR : GetFileVersionInfoA failed!\n");
    return 0;
  };
  if (!VerQueryValueA(v, "\\", (void**)Version, (unsigned int*)&dwRet ) ) {
    trace("dbg.GetFileVersion : ERROR : VerQueryValueA failed!\n");
    return 0;
  }; 
  return dwRet;
};

// DbgWriteMinidump
//
BOOL __stdcall DbgWriteDump( HANDLE hProcess, DWORD dwProcessID, DWORD dwThreadID, const char* szFileName, EXCEPTION_POINTERS* ExPtrs, MINIDUMP_USER_STREAM* UserData ) {
  
  // Требования : szFileName, ExPtrs и UserData могут быть NULL.
  //   Exception, описываемый структурой ExPtrs, должен быть срайзан в потоке с ID dwThreadID.
  //   Поле Type в структуре UserData игнорируется.
  //

  // TODO : Если ExPtrs == NULL, создать новый поток, в нём вызвать MiniDumpWriteDump и
  //          с помощью CallbackParam отфильтровать этот поток из дампа, 
  //          ибо DbgHelp неправильно создаёт трэйс стека, если ему не дали ExceptionParam.
  
  // TODO : Write MINIDUMP_SYSTEM_INFO in UserStreamParam

  if( szFileName!=NULL && !assert(!IsBadStringPtr(szFileName, MAX_PATH)) ) {
    SetLastError(ERROR_INVALID_PARAMETER);
    return false;
  };
  if( ExPtrs!=NULL && !assert(!IsBadReadPtr(ExPtrs, sizeof(EXCEPTION_POINTERS))) ) {
    SetLastError(ERROR_INVALID_PARAMETER);
    return false;    
  };
  if( UserData!=NULL && !assert(!IsBadReadPtr(UserData, sizeof(UserData))) ) {
    SetLastError(ERROR_INVALID_PARAMETER);
    return false;        
  };

  hDumpFile = CreateFile(szFileName ? szFileName : szDumpFileName, GENERIC_WRITE, 
                              0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
  if( hDumpFile==INVALID_HANDLE_VALUE )  return false;

  register MINIDUMP_EXCEPTION_INFORMATION* ExceptInfo = NULL;
  if( ExPtrs!=NULL ) {
    ExInfo.ThreadId = dwThreadID;
    ExInfo.ExceptionPointers = ExPtrs;
    ExInfo.ClientPointers = true;
    ExceptInfo = &ExInfo;
  };
  register MINIDUMP_USER_STREAM_INFORMATION* UserInfo = NULL; 
  if( UserData!=NULL ) {  
    UserStream.UserStreamCount = 1;
    UserStream.UserStreamArray = UserData;
    UserInfo = &UserStream;
  };
  
  if( !MiniDumpWriteDump(hProcess, dwProcessID, hDumpFile, (MINIDUMP_TYPE)(MiniDumpWithProcessThreadData | MiniDumpWithPrivateReadWriteMemory | MiniDumpWithIndirectlyReferencedMemory | MiniDumpWithUnloadedModules | MiniDumpWithHandleData | MiniDumpWithDataSegs), 
    ExceptInfo, UserInfo, NULL ) ) {
    CloseHandle(hDumpFile);
    return false;  
   } else {
    CloseHandle(hDumpFile);
    return true;
  };
};