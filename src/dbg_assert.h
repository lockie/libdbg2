// assert & trace functions
//

#include <stdio.h>
#include <stdlib.h>
#include <varargs.h>
#include <signal.h>

#include <windows.h>
               
#include "dbg2.h"

               
static char aBuff[DBG_BUFF_SIZE];

static DWORD dwTraceOpts[3];
static HANDLE hOutFile[3];

    
// DbgSetReportMode
//
DWORD __stdcall DbgSetReportMode(DWORD dwReportType, DWORD dwReportMode ) {
  if( dwReportType > 3 || dwReportType < 1 )    return 0; 
  DWORD register dwRet;
  dwRet = dwTraceOpts[dwReportType];
  dwTraceOpts[dwReportType] = dwReportMode;
  return dwRet;
};


// DbgSetReportFile
//
HANDLE __stdcall DbgSetReportFile(DWORD dwReportType, HANDLE hFile ) {
  if( dwReportType > 3 || dwReportType < 1 )    return NULL;
  HANDLE register hRet;
  hRet = hOutFile[dwReportType];
  hOutFile[dwReportType] = hFile;
  return hRet;
};



// Function : DbgAssert
// Parameters:
//   bDoStackTrace - if TRUE, stack trace will be added to report
//   szFunc        - name of function (use macro __FUNC__ or __FUNCSIG__) 
//   szFile        - name of file witch source code called assert (use macro __FILE__) 
//   dwLide        - # of string in source code with call of assert (use macro __LINE__)
//   szExpr        - expression with which called assert
// 
// Return value :
//   TRUE          - continue code execution
//   FALSE         - break in debugger
//   <None>        - terminated program =)
//
//
BOOL __stdcall DbgAssert( BOOL bDoStackTrace, const char* szFunc, const char* szFile, DWORD dwLine, const char* szExpr) {   
  register unsigned long ulOldErr = GetLastError();
  register unsigned long dwLen;

  dwLen = sprintf(aBuff, "Debug Assertion failure!\n\nProgram : ");
  dwTemp = GetModuleFileName(NULL, &aBuff[dwLen], DBG_BUFF_SIZE - dwLen);
  if (dwTemp!=0) {
    dwLen+=dwTemp;
   } else {
    lstrcpyn(&aBuff[dwLen], "<unknown>", 10);
    dwLen+=9;
  };
  dwLen+=sprintf(&aBuff[dwLen], "\nFile : %s\nFunction : %s\nLine : %u\nExpression : %s\nLast error (%u) : ", 
    szFile, szFunc, dwLine, szExpr, ulOldErr);
  dwTemp = (
    FormatMessage( FORMAT_MESSAGE_IGNORE_INSERTS |
                   FORMAT_MESSAGE_FROM_SYSTEM,                   
                   NULL,
                   ulOldErr,
                   0 ,
                   &aBuff[dwLen],
                   DBG_BUFF_SIZE - dwLen,
                   0         ) * sizeof ( TCHAR ) );
  
  if ( dwTemp == 0 ) {
    lstrcpyn(&aBuff[dwLen], "<unknown>\r\n\x00", 12);
    dwLen+=11;
   } else {
    dwLen+=dwTemp;
  };
    
/*
  if ( RMA_DOSTACKTRACE == ( RMA_DOSTACKTRACE & dwTraceOpts ) ) {    
    if (GetThreadContext(GetCurrentThread(), &cont)) {
      dwLen+=sprintf(&aBuff[dwLen], "Stack back trace:\n");
      
      // GetFirstStackTrace =)
      if (!EnumModules()) return 0; // to get maxlen  
  
      ZeroMemory(&stframe, sizeof(stframe));
      SetAddress(stframe.AddrPC,     cont.Eip);
      SetAddress(stframe.AddrFrame,  cont.Ebp);
      SetAddress(stframe.AddrStack,  cont.Esp);
      //SetAddress(stframe.AddrReturn, 0);
      //SetAddress(stframe.AddrBStore, 0);
  

    };                        
  };   */

  
  // Do stack trace?
  if( bDoStackTrace ) {  
    SymSetOptions( SYMOPT_CASE_INSENSITIVE | SYMOPT_DEFERRED_LOADS | 
      /*SYMOPT_LOAD_ANYTHING |*/ SYMOPT_LOAD_LINES | SYMOPT_UNDNAME );
    SymInitialize(GetCurrentProcess(), NULL, true);
    //GetFirstStackTrace();
    // TODO : TODO !!
  };
      
  // Output resulting string... 
  if ( DBG_MODE_ODS == ( DBG_MODE_ODS &  dwTraceOpts[3]) )   OutputDebugString(aBuff);      
  if ( DBG_MODE_STDERR == ( DBG_MODE_STDERR & dwTraceOpts[3]) )  fprintf(stderr, "%s\n", aBuff);  
  if ( DBG_MODE_FILE == ( DBG_MODE_FILE & dwTraceOpts[3] ) )  WriteFile(hOutFile, aBuff, dwLen, &dwTemp, NULL); 
   
  // handle an assert... 
  if ( DBG_MODE_MSGBOX == ( DBG_MODE_MSGBOX & dwTraceOpts[3] ) ) {
    strcpy(&aBuff[dwLen], "\n\nAbort   -  terminate\nRetry   -  debug\nIgnore  -  ignore");    
    dwTemp = MessageBox(NULL, aBuff, "ASSERTION FAILURE", 
      MB_ABORTRETRYIGNORE | MB_ICONERROR | MB_TASKMODAL | MB_DEFBUTTON2);  
    if (dwTemp == IDRETRY) {
      SetLastError(ulOldErr);    
      return false;
    };
    if (dwTemp == IDIGNORE) {
      SetLastError(ulOldErr);
      return true;
    };
    //raise(SIGABRT);
    TerminateProcess(GetCurrentProcess(), 3);  // TODO : Жестоковато =)
  };
  // default handling - debug ("Retry")
  SetLastError(ulOldErr);    
  return false;   
};


