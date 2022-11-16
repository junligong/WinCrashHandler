#pragma once

#include <map>
#include <vector>
#include <sstream>
#include <tchar.h>
#include "windows.h"

struct FunctionCall
{
    DWORD64 Address;
    std::string ModuleName;
    std::string FunctionName;
    std::string FileName;
    int			LineNumber;

public:
    FunctionCall() :
        Address(0),
        ModuleName(""),
        FunctionName(""),
        FileName(""),
        LineNumber(0)
    {
    }

public:
    static std::string GetFileName(const std::string& fullpath)
    {
        size_t index = fullpath.find_last_of('\\');
            if (index == std::string::npos)
            {
                return fullpath;
            }

        return fullpath.substr(index + 1);
    }
};

class StackTracer
{
public:
    static std::string GetExceptionStackTrace(LPEXCEPTION_POINTERS e);

private:
    // Always return EXCEPTION_EXECUTE_HANDLER after getting the call stack
    LONG ExceptionFilter(LPEXCEPTION_POINTERS e);

    // return the exception message along with call stacks
    std::string GetExceptionMsg();

    // Return exception code and call stack data structure so that 
    // user could customize their own message format
    DWORD GetExceptionCode();
    std::vector<FunctionCall> GetExceptionCallStack();

private:
    StackTracer(void);
    ~StackTracer(void);

    // The main function to handle exception
    LONG __stdcall HandleException(LPEXCEPTION_POINTERS e);

    // Work through the stack upwards to get the entire call stack
    void TraceCallStack(CONTEXT* pContext);

private:
    DWORD m_dwExceptionCode;

    std::vector<FunctionCall> m_vecCallStack;

    typedef std::map<DWORD, const char*> CodeDescMap;
    CodeDescMap m_mapCodeDesc;

    DWORD m_dwMachineType; // Machine type matters when trace the call stack (StackWalk64)

};