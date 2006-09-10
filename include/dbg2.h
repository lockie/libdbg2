
#ifndef __DBG2_H__
#define __DBG2_H__  1

// target OS is Windows XP
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0501
#endif

#include <windows.h>
#include <dbghelp.h>
#include <winver.h>

#ifdef __BORLANDC__
#define __FUNCSIG__  __FUNC__
#define __forceinline inline
#endif // __BORLANDC__

#ifdef DBG_SOURCE
#define DBG_API __declspec(dllexport) 
#else
#pragma comment(lib, "dbg2.lib")
#define DBG_API __declspec(dllimport)
#endif
#define DBG_CALL __stdcall


#ifdef __cplusplus
extern "C" {
#endif

BOOL   DBG_API DBG_CALL InitDbg ( const char* szSymsPath, const char* szDumpFilename = NULL );

DWORD  DBG_API DBG_CALL DbgSetReportMode( DWORD dwReportType, DWORD dwReportMode );
HANDLE DBG_API DBG_CALL DbgSetReportFile( DWORD dwReportType, HANDLE hFile );

BOOL   DBG_API DBG_CALL DbgAssert( BOOL bDoStackTrace, const char* szFunc, 
                                    const char* szFile, DWORD dwLine, const char* szExpr); 

DWORD   DBG_API DBG_CALL DbgGetFileVersion( const char* FileName, VS_FIXEDFILEINFO** Version );

BOOL    DBG_API DBG_CALL DbgWriteDump( HANDLE hProcess, DWORD dwProcessID, DWORD dwThreadID, 
                                         const char* szFileName, EXCEPTION_POINTERS* ExPtrs, MINIDUMP_USER_STREAM* UserData = NULL );


#ifdef __BORLANDC__     // ...name mangling trick.
BOOL  DBG_API __cdecl  Trace();
#else
BOOL  DBG_API __cdecl  _Trace();
#endif  // __BORLANDC__


// assert macro 
// 
#ifdef assert
#undef assert
#endif

#ifdef ASSERT
#undef ASSERT
#endif

#ifdef trace
#undef trace
#endif

#ifdef TRACE
#undef TRACE
#endif

#ifdef _DEBUG
#define assert(Expression) (BOOL)(Expression ? true : \
  (DbgAssert(false, __FUNCSIG__, __FILE__, __LINE__, #Expression) ? false : dbg_break()) )
#define SUPERASSERT(Expression) (BOOL)(Expression ? true : \
  (DbgAssert(true, __FUNCSIG__, __FILE__, __LINE__, #Expression) ? false : dbg_break()) )
#define ASSERT assert
#define VERIFY assert
#ifdef __BORLANDC__
//#define trace(expr, ...) DbgAssert(__FUNCSIG__, __FILE__, __LINE__, expr, __VA_ARGS__)
#else  // __BORLANDC__
#define trace 
#endif // __BORLANDC__
#define TRACE trace
#else   // _DEBUG
#define assert(Expression) (BOOL)(Expression)
#define SUPERASSERT(Expression) (BOOL)(Expression)
#define VERIFY(Expression) (BOOL) (Expression)
#define trace __noop
#endif  // _DEBUG


// dbg_break  (you need to allow your linker make it inline!)
//
BOOL __forceinline dbg_break() { 
  if (!IsDebuggerPresent()) return false;
    else {
      DebugBreak();
      return true;
  };
};


// Trace \ Assert flags
#define DBG_INFO              0x0001
#define DBG_WARN              0x0002
#define DBG_ASSERT            0x0003
// assert is also error.
#define DBG_MODE_ODS          0x0001
#define DBG_MODE_FILE         0x0002
#define DBG_MODE_STDERR       0x0004
#define DBG_MODE_MSGBOX       0x0008


#ifdef __cplusplus
}; 
#endif

#endif  // __DBG2_H__
