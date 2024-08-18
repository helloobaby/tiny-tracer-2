/*
* TinyTracer, CC by: hasherezade@gmail.com
* Runs with: Intel PIN (https://software.intel.com/en-us/articles/pin-a-dynamic-binary-instrumentation-tool)
*
* Prints to <output_file> addresses of transitions from one sections to another
* (helpful in finding OEP of packed file)
* args:
* -m    <module_name> ; Analysed module name (by default same as app name)
* -o    <output_path> Output file
*
*/
#include "pin.H"

#include <iostream>
#include <string>
#include <set>
#include <sstream>

#include "TinyTracer.h"

#include "ProcessInfo.h"
#include "TraceLog.h"
#include "PinLocker.h"

#define TOOL_NAME "TinyTracer"
#define VERSION "7.777"

#include "Util.h"
#include "Settings.h"
#define LOGGED_ARGS_MAX 11

#define USE_ANTIDEBUG
#define USE_ANTIVM

#ifndef _WIN32
#undef USE_ANTIDEBUG // works only for Windows!
#undef USE_ANTIVM
#endif

#ifdef USE_ANTIDEBUG
#include "AntiDebug.h"
#include "Anti.h"
#endif

#ifdef USE_ANTIVM
#include "AntiVm.h"
#endif

/* ================================================================== */
// Global variables 
/* ================================================================== */

Settings m_Settings;
ProcessInfo pInfo;
TraceLog traceLog;

// last shellcode to which the transition got redirected:
std::set<ADDRINT> m_tracedShellc;

/* ===================================================================== */
// Command line switches
/* ===================================================================== */
KNOB<std::string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool",
    "o", "", "Specify file name for the output");

KNOB<std::string> KnobIniFile(KNOB_MODE_WRITEONCE, "pintool",
    "s", "", "Specify the settings file");

KNOB<std::string> KnobModuleName(KNOB_MODE_WRITEONCE, "pintool",
    "m", "", "Analysed module name (by default same as app name)");

KNOB<std::string> KnobWatchListFile(KNOB_MODE_WRITEONCE, "pintool",
    "b", "", "A list of watched functions (dump parameters before the execution)");

KNOB<std::string> KnobSyscallsTable(KNOB_MODE_WRITEONCE, "pintool",
    "l", "", "Syscall table: a CSV file mapping a syscall ID (in hex) to a function name");

KNOB<std::string> KnobExcludedListFile(KNOB_MODE_WRITEONCE, "pintool",
    "x", "", "A list of functions excluded from watching");

KNOB<std::string> KnobStopOffsets(KNOB_MODE_WRITEONCE, "pintool",
    "p", "", "A list of stop offsets: RVAs of the traced module where the execution should pause");

/* ===================================================================== */
// Utilities

/* ===================================================================== */

VOID _LogFunctionArgs(const ADDRINT Address, const CHAR* name, uint32_t argCount, VOID* arg1, VOID* arg2, VOID* arg3, VOID* arg4, VOID* arg5, VOID* arg6, VOID* arg7, VOID* arg8, VOID* arg9, VOID* arg10, VOID* arg11);


/*!
*  Print out help message.
*/
INT32 Usage()
{
    std::cerr << "This tool prints out : " << std::endl <<
        "Addresses of redirections into to a new sections. Called API functions.\n" << std::endl;

    std::cerr << KNOB_BASE::StringKnobSummary() << std::endl;
    return -1;
}

/* ===================================================================== */
// Analysis utilities
VOID Log(BOOL now, const char* fmt ,...)
{
    va_list argptr;
    va_start(argptr, fmt);
    char inBuffer[0x1000];
    sprintf_s(inBuffer, 0x1000,fmt, argptr);
    va_end(argptr);
    LOG(inBuffer);
}
#if _WIN64
VOID printContext(const CONTEXT* ctx, UINT32 c)
{
    Log(TRUE, "\nRAX = %p\tRBX = %p\tRCX = %p\nRDX = %p\tRSI = %p\tRDI = %p\nRBP = %p\tRSP = %p\tRIP = %p\n",
        PIN_GetContextReg(ctx, REG_RAX),
        PIN_GetContextReg(ctx, REG_RBX),
        PIN_GetContextReg(ctx, REG_RCX),
        PIN_GetContextReg(ctx, REG_RDX),
        PIN_GetContextReg(ctx, REG_RSI),
        PIN_GetContextReg(ctx, REG_RDI),
        PIN_GetContextReg(ctx, REG_RBP),
        PIN_GetContextReg(ctx, REG_RSP),
        PIN_GetContextReg(ctx, REG_RIP));
    // TODO: use the safe copy API
    UINT count = ((c == -1) ? ((PIN_GetContextReg(ctx, REG_RBP)-PIN_GetContextReg(ctx, REG_RSP))/sizeof(ADDRINT))+1 : c);
    ADDRINT *ptr = (ADDRINT*)PIN_GetContextReg(ctx, REG_RSP);
    for (UINT32 i = 0; i < count; i++) {
    	Log(TRUE, "[%08x]: %08x\n", ptr, *ptr);
    	ptr++;
    }
}
#else
VOID printContext(const CONTEXT* ctx, UINT32 c)
{
    Log(TRUE, "\nEAX = %08x\tEBX = %08x\tECX = %08x\nEDX = %08x\tESI = %08x\tEDI = %08x\nEBP = %08x\tESP = %08x\tEIP = %08x\n",
        PIN_GetContextReg(ctx, REG_EAX),
        PIN_GetContextReg(ctx, REG_EBX),
        PIN_GetContextReg(ctx, REG_ECX),
        PIN_GetContextReg(ctx, REG_EDX),
        PIN_GetContextReg(ctx, REG_ESI),
        PIN_GetContextReg(ctx, REG_EDI),
        PIN_GetContextReg(ctx, REG_EBP),
        PIN_GetContextReg(ctx, REG_ESP),
        PIN_GetContextReg(ctx, REG_EIP));
    // TODO: use the safe copy API
    UINT count = ((c == -1) ? ((PIN_GetContextReg(ctx, REG_EBP) - PIN_GetContextReg(ctx, REG_ESP)) / sizeof(VOID*)) + 1 : c);
    ADDRINT* ptr = (ADDRINT*)PIN_GetContextReg(ctx, REG_ESP);
    for (UINT32 i = 0; i < count; i++) {
        Log(TRUE, "[%08x]: %08x\n", ptr, *ptr);
        ptr++;
    }
}

#endif
/* ===================================================================== */

BOOL isInTracedShellc(const ADDRINT addr)
{
    if (addr == UNKNOWN_ADDR) {
        return FALSE;
    }
    const ADDRINT regionBase = query_region_base(addr);
    if (regionBase == UNKNOWN_ADDR) {
        return FALSE;
    }
    if (m_tracedShellc.find(regionBase) != m_tracedShellc.end()) {
        return TRUE;
    }
    return FALSE;
}

WatchedType isWatchedAddress(const ADDRINT Address)
{
    if (Address == UNKNOWN_ADDR) {
        return WatchedType::NOT_WATCHED;
    }
    const IMG currModule = IMG_FindByAddress(Address);
    const bool isCurrMy = pInfo.isMyAddress(Address);
    if (isCurrMy) {
        return WatchedType::WATCHED_MY_MODULE;
    }
    const BOOL isShellcode = !IMG_Valid(currModule);
    if (m_Settings.followShellcode && isShellcode) {
        if (m_Settings.followShellcode == SHELLC_FOLLOW_ANY) {
            return WatchedType::WATCHED_SHELLCODE;
        }
        if (isInTracedShellc(Address)){
            return WatchedType::WATCHED_SHELLCODE;
        }
    }
    return WatchedType::NOT_WATCHED;;
}

/* ===================================================================== */
// Analysis routines
/* ===================================================================== */

inline ADDRINT getReturnFromTheStack(const CONTEXT* ctx)
{
    if (!ctx) return UNKNOWN_ADDR;
    ADDRINT retAddr = UNKNOWN_ADDR;
    const ADDRINT* stackPtr = reinterpret_cast<ADDRINT*>(PIN_GetContextReg(ctx, REG_STACK_PTR));
    size_t copiedSize = PIN_SafeCopy(&retAddr, stackPtr, sizeof(retAddr));
    if (copiedSize != sizeof(retAddr)) {
        LOG("getReturnFromTheStack fail\n");
        return UNKNOWN_ADDR;
    }
    return retAddr;
}

inline VOID setReturnFromTheStack(const CONTEXT* ctx,ADDRINT AddrTo) {
    if (!ctx) return;
    const ADDRINT* stackPtr = reinterpret_cast<ADDRINT*>(PIN_GetContextReg(ctx, REG_STACK_PTR));
    size_t copiedSize = PIN_SafeCopy((void*)stackPtr, &AddrTo, sizeof(AddrTo));
    if (copiedSize != sizeof(AddrTo)) {
        // TODO : BUG Report
        LOG("setReturnFromTheStack fail\n");
        return;
    }

    return;
}

VOID _SaveTransitions(const ADDRINT addrFrom, const ADDRINT addrTo, BOOL isIndirect, const CONTEXT* ctx = NULL)
{
    const WatchedType fromWType = isWatchedAddress(addrFrom); // is the call from the traced area?

    const bool isTargetMy = pInfo.isMyAddress(addrTo);
    const bool isCallerMy = pInfo.isMyAddress(addrFrom);

    IMG targetModule = IMG_FindByAddress(addrTo);
    IMG callerModule = IMG_FindByAddress(addrFrom);
    const bool isCallerPeModule = IMG_Valid(callerModule);
    const bool isTargetPeModule = IMG_Valid(targetModule);


    /**
    is it a transition from the traced module to a foreign module?
    */
    if (fromWType == WatchedType::WATCHED_MY_MODULE // 返回地址在本模块
        && !isTargetMy) // 目标地址不在本模块
    {
        ADDRINT RvaFrom = addr_to_rva(addrFrom);
        if (isTargetPeModule) { // 是否在一个模块内
            const std::string func = get_func_at(addrTo);
            const std::string dll_name = IMG_Name(targetModule);
            // 判断是否是要过滤的函数
            if (m_Settings.excludedFuncs.contains(dll_name, func)) {
                return;
            }
            traceLog.logCall(0, RvaFrom, true, dll_name, func);
        }
        else {
            //not in any of the mapped modules:
            const ADDRINT pageTo = query_region_base(addrTo);

            m_tracedShellc.insert(pageTo); //save the beginning of this area
            traceLog.logCall(0, RvaFrom, pageTo, addrTo);
        }
    }

    /**
    trace calls from witin a shellcode:
    */
    if (fromWType == WatchedType::WATCHED_SHELLCODE) { // 这种情况一般是跟踪Shellcode里面调用系统API

        const ADDRINT pageFrom = query_region_base(addrFrom);
        const ADDRINT pageTo = query_region_base(addrTo);

        if (isTargetPeModule) { // it is a call to a module
            const std::string func = get_func_at(addrTo);
            const std::string dll_name = IMG_Name(targetModule);
            if (m_Settings.excludedFuncs.contains(dll_name, func)) {
                return;
            }
            traceLog.logCall(pageFrom, addrFrom, false, dll_name, func);
        }
        // Shellcode跳转到另一个shellcode
        // 这里作者处理的不好,判断是否是同一块shellcode有点太粗糙了
        else if (pageFrom != pageTo) // it is a call to another shellcode 
        {
            // add the new shellcode to the set of traced
            if (m_Settings.followShellcode == SHELLC_FOLLOW_RECURSIVE) {
                m_tracedShellc.insert(pageTo);
            }

            // register the transition
            if (m_Settings.logShelcTrans) {
                // save the transition from one shellcode to the other
                ADDRINT base = get_base(addrFrom);
                ADDRINT RvaFrom = addrFrom - base;
                traceLog.logCall(base, RvaFrom, pageTo, addrTo);
            }
        }

    }

    /**
    save the transition when a shellcode returns to a traced area from an API call:
    */
    if (fromWType == WatchedType::WATCHED_SHELLCODE // 从shellcode返回
        && isTargetPeModule // 返回到一个模块内
        && ctx //the context was passed: we can check the return
        )
    {
        //std::cout << std::hex << "addrFrom " << addrFrom << std::endl;
        
        // was the shellcode a proxy for making an API call?
        const ADDRINT returnAddr = getReturnFromTheStack(ctx); // 
        const WatchedType toWType = isWatchedAddress(returnAddr); // does it return into the traced area?
        if (toWType != WatchedType::NOT_WATCHED) { // 这里有两种情况,一种是返回到我们的观察模块,一种是又返回到另一块shellcode
            const std::string func = get_func_at(addrTo);
            const std::string dll_name = IMG_Name(targetModule);
            const ADDRINT pageRet = get_base(returnAddr);
            const ADDRINT RvaFrom = addr_to_rva(addrFrom);
            const ADDRINT base = get_base(addrFrom);

            traceLog.logCallRet(base, RvaFrom, pageRet, returnAddr, dll_name, func);
        }
    }

    /**
    trace transitions between the sections of the traced module:
    */
    if (isTargetMy) {
        ADDRINT rva = addr_to_rva(addrTo); // convert to RVA

        // is it a transition from one section to another?
        if (pInfo.updateTracedModuleSection(rva)) {
            if (m_Settings.logSectTrans) {
                const s_module* sec = pInfo.getSecByAddr(rva);
                std::string curr_name = (sec) ? sec->name : "?";
                if (isCallerMy) {
                    ADDRINT rvaFrom = addr_to_rva(addrFrom); // convert to RVA
                    const s_module* prev_sec = pInfo.getSecByAddr(rvaFrom);
                    std::string prev_name = (prev_sec) ? prev_sec->name : "?";
                    traceLog.logNewSectionCalled(rvaFrom, prev_name, curr_name);
                }
                traceLog.logSectionChange(rva, curr_name);
            }
        }
    }
}

VOID SaveTransitions(const ADDRINT prevVA, const ADDRINT Address, BOOL isIndirect, const CONTEXT* ctx = NULL)
{
    PinLocker locker;
    _SaveTransitions(prevVA, Address, isIndirect, ctx);
}

VOID LogMsgAtAddress(const WatchedType wType, const ADDRINT Address, const char* label, const char* msg, const char* link)
{
    if (!msg) return;
    if (wType == WatchedType::NOT_WATCHED) return;

    std::stringstream ss;
    ADDRINT rva = UNKNOWN_ADDR;
    if (wType == WatchedType::WATCHED_MY_MODULE) {
        rva = addr_to_rva(Address); // convert to RVA
    }
    else if (wType == WatchedType::WATCHED_SHELLCODE) {
        const ADDRINT start = query_region_base(Address);
        rva = Address - start;
        if (start != UNKNOWN_ADDR) {
            ss << "> " << std::hex << start << "+";
        }
    }
    if (rva == UNKNOWN_ADDR) return;
    ss << std::hex << rva << TraceLog::DELIMITER;
    if (label) {
        ss << label;
    }
    ss << msg;
    if (link) {
        ss << TraceLog::DELIMITER << link;
    }
    traceLog.logLine(ss.str());
}

VOID RdtscCalled(const CONTEXT* ctxt)
{
    PinLocker locker;

    const ADDRINT Address = (ADDRINT)PIN_GetContextReg(ctxt, REG_INST_PTR);

    const WatchedType wType = isWatchedAddress(Address);
    if (wType == WatchedType::NOT_WATCHED) return;

    LogMsgAtAddress(wType, Address, nullptr, "RDTSC", nullptr);
}

VOID PauseAtOffset(const CONTEXT* ctxt)
{
    PinLocker locker;
    if (!m_Settings.stopOffsets.size()) return;

    const ADDRINT Address = (ADDRINT)PIN_GetContextReg(ctxt, REG_INST_PTR);
    const WatchedType wType = isWatchedAddress(Address);
    if (wType != WatchedType::WATCHED_MY_MODULE) return;

    const std::string prompt = "TT> ";
    ADDRINT rva = addr_to_rva(Address); // convert to RVA
    if (m_Settings.stopOffsets.find(rva) != m_Settings.stopOffsets.end()) {
        std::cout << "Stop offset reached: " << std::hex << rva << ". Press 'C' to continue, '?' for more info...\n";
        char cmd = '?';
        while (true) {
            std::cout << prompt;
            std::cin >> cmd;

            if (cmd == 'C') break;
            else if (cmd == '?') {
                std::cout << "Available commands:\n"
                    << "C - continue execution\n"
                    << "D - delete the current stop offset (" << std::hex << rva << ")\n"
                    << "F - print the path to the file where the stop offsets are defined\n"
                    << "P - print active stop offsets\n"
                    << "? - info: print all available commands\n"
                    << std::endl;
            }
            else if (cmd == 'D') {
                m_Settings.stopOffsets.erase(rva);
                std::cout << "Stop offset deleted.\n";
            }
            else if (cmd == 'F') {
                std::cout << "Stop offsets defined in: " << KnobStopOffsets.ValueString() << "\n";
            }
            else if (cmd == 'P') {
                if (m_Settings.stopOffsets.size() == 0) {
                    std::cout << "No active stop offsets\n";
                    continue;
                }
                std::cout << "Active stop offsets:\n";
                for (auto it = m_Settings.stopOffsets.begin(); it != m_Settings.stopOffsets.end(); ++it) {
                    std::cout << std::hex << *it << "\n";
                }
            }
            else if (isalnum(cmd)) {
                std::cout << "Invalid command: " << cmd << "\n";
            }
        }
        std::cout << "Continuing the execution...\n";
    }
}

VOID CpuidCalled(const CONTEXT* ctxt)
{
    PinLocker locker;
    const std::string mnem = "CPUID";

    const ADDRINT Address = (ADDRINT)PIN_GetContextReg(ctxt, REG_INST_PTR);

    const WatchedType wType = isWatchedAddress(Address);
    if (wType == WatchedType::NOT_WATCHED) return;

    ADDRINT Param = (ADDRINT)PIN_GetContextReg(ctxt, REG_GAX);
    if (wType == WatchedType::WATCHED_MY_MODULE) {
        ADDRINT rva = addr_to_rva(Address); // convert to RVA
        traceLog.logInstruction(0, rva, mnem, Param);
    }
    if (wType == WatchedType::WATCHED_SHELLCODE) {
        const ADDRINT start = query_region_base(Address);
        ADDRINT rva = Address - start;
        if (start != UNKNOWN_ADDR) {
            traceLog.logInstruction(start, rva, mnem, Param);
        }
    }
}

BOOL fetchInterruptID(const ADDRINT Address, int &intID)
{
    unsigned char copyBuf[2] = { 0 };
    int fetchedSize = 1;
    std::string mnem;
    if (!PIN_FetchCode(copyBuf, (const void*)Address, fetchedSize, NULL)) return FALSE;

    if (copyBuf[0] == 0xCD) { // INT
        fetchedSize = 2;
        if (!PIN_FetchCode(copyBuf, (const void*)Address, fetchedSize, NULL)) return FALSE;
    }
    switch (copyBuf[0]) {
        case 0xCC:
            intID = 3; break;
        case 0xCE:
            intID = 4; break;
        case 0xF1:
            intID = 1; break;
        case 0xCD:  // 常规INT指令
        {
            intID = (unsigned int)copyBuf[1];
            break;
        }
        default:
            return false;
    }
    return TRUE;
}

VOID InterruptCalled(const CONTEXT* ctxt)
{
    PinLocker locker;
    const ADDRINT Address = (ADDRINT)PIN_GetContextReg(ctxt, REG_INST_PTR);
    const WatchedType wType = isWatchedAddress(Address);
    if (wType == WatchedType::NOT_WATCHED) {
        return;
    }
    int interruptID = 0;
    if (!fetchInterruptID(Address, interruptID)) return;

    const std::string mnem = "INT";
    if (wType == WatchedType::WATCHED_MY_MODULE) {
        ADDRINT rva = addr_to_rva(Address); // convert to RVA
        traceLog.logInstruction(0, rva, mnem, interruptID);
    }
    if (wType == WatchedType::WATCHED_SHELLCODE) {
        const ADDRINT start = query_region_base(Address);
        ADDRINT rva = Address - start;
        if (start != UNKNOWN_ADDR) {
            traceLog.logInstruction(start, rva, mnem, interruptID);
        }
    }
}

VOID LogSyscallsArgs(const CHAR* name, const CONTEXT* ctxt, SYSCALL_STANDARD std, const ADDRINT Address, uint32_t argCount)
{
    const size_t args_max = LOGGED_ARGS_MAX;
    VOID* syscall_args[args_max] = { 0 };

    for (size_t i = 0; i < args_max; i++) {
        if (i == argCount) break;
        syscall_args[i] = reinterpret_cast<VOID*>(PIN_GetSyscallArgument(ctxt, std, i));
    }
    _LogFunctionArgs(Address,
        name, argCount,
        syscall_args[0],
        syscall_args[1],
        syscall_args[2],
        syscall_args[3],
        syscall_args[4],
        syscall_args[5],
        syscall_args[6],
        syscall_args[7],
        syscall_args[8],
        syscall_args[9],
        syscall_args[10]);
}


VOID SyscallCalled(THREADID tid, CONTEXT* ctxt, SYSCALL_STANDARD std, VOID* v)
{
    PinLocker locker;
#ifdef _WIN64
    // Since Windows 10 TH2, NTDLL's syscall routines have changed: syscalls can
    // now be performed with the SYSCALL instruction, and with the INT 2E
    // instruction. The ABI is the same in both cases.
    if (std == SYSCALL_STANDARD_WINDOWS_INT) {
        const auto* insPtr = reinterpret_cast<ADDRINT*>(PIN_GetContextReg(ctxt, REG_INST_PTR));
        uint16_t instruction = 0;
        PIN_SafeCopy(&instruction, insPtr, sizeof(instruction));
        if (instruction != 0x2ECD) { // INT 2E
            // Not a relevant interrupt, return now.
            return;
        }
        std = SYSCALL_STANDARD_IA32E_WINDOWS_FAST;
    }
#endif

    const auto address = [&]() -> ADDRINT {
        if (std == SYSCALL_STANDARD_WOW64) {
            // Note: In this case, the current instruction address is in a 64-bit
            // code portion. The address that we're interested in is the return
            // address, which is in a 32-bit code portion.
            return getReturnFromTheStack(ctxt);
        }
        return PIN_GetContextReg(ctxt, REG_INST_PTR);
    }();
    
    const WatchedType wType = isWatchedAddress(address);
    if (wType == WatchedType::NOT_WATCHED) return;
    
    const ADDRINT syscallNum = PIN_GetSyscallNumber(ctxt, std);
    if (syscallNum == UNKNOWN_ADDR) return; //invalid
    //std::cout << "syscallNum " << syscallNum << std::endl;

    std::string funcName = m_Settings.syscallsTable.getName(syscallNum);

    if (wType == WatchedType::WATCHED_MY_MODULE) {
        ADDRINT rva = addr_to_rva(address); // convert to RVA
        traceLog.logSyscall(0, rva, syscallNum, funcName);
    }
    else if (wType == WatchedType::WATCHED_SHELLCODE) {
        const ADDRINT start = query_region_base(address);
        ADDRINT rva = address - start;
        if (start != UNKNOWN_ADDR) {
            traceLog.logSyscall(start, rva, syscallNum, funcName);
        }
    }

    // Log arguments if needed:
    // 
    // check if it is watched by the syscall number:
    const auto& it = m_Settings.funcWatch.syscalls.find(syscallNum);
    if (it != m_Settings.funcWatch.syscalls.end()) {
        LogSyscallsArgs(WSyscallInfo::formatSyscallName(syscallNum).c_str(), ctxt, std, address, it->second.paramCount);
        return;
    }
#ifdef _WIN32 // supported only for Windows
    // check if it is watched by the function name:
    std::string syscallFuncName = SyscallsTable::convertNameToNt(m_Settings.syscallsTable.getName(syscallNum));
    for (size_t i = 0; i < m_Settings.funcWatch.funcs.size(); i++) {
        if (util::iequals("ntdll", m_Settings.funcWatch.funcs[i].dllName)
            || util::iequals("win32u", m_Settings.funcWatch.funcs[i].dllName))
        {
            std::string funcName = SyscallsTable::convertNameToNt(m_Settings.funcWatch.funcs[i].funcName);
            if (syscallFuncName == funcName) {
                LogSyscallsArgs(funcName.c_str(), ctxt, std, address, m_Settings.funcWatch.funcs[i].paramCount);
                break;
            }
        }
    }
#endif
}

ADDRINT _setTimer(const CONTEXT* ctxt, bool isEax)
{
    static UINT64 Timer = 0;
    UINT64 result = 0;

    if (Timer == 0) {
        ADDRINT edx = (ADDRINT)PIN_GetContextReg(ctxt, REG_GDX);
        ADDRINT eax = (ADDRINT)PIN_GetContextReg(ctxt, REG_GAX);
        Timer = (UINT64(edx) << 32) | eax;
    }
    else {
        Timer += 50;
    }

    if (isEax) {
        result = (Timer << 32) >> 32;
    }
    else {
        result = (Timer) >> 32;
    }
    return (ADDRINT)result;
}

ADDRINT AlterRdtscValueEdx(const CONTEXT* ctxt)
{
    PinLocker locker;
    return _setTimer(ctxt, false);
}

ADDRINT AlterRdtscValueEax(const CONTEXT* ctxt)
{
    PinLocker locker;
    return _setTimer(ctxt, true);
}

/* ===================================================================== */
// Instrument functions arguments
/* ===================================================================== */

BOOL isValidReadPtr(VOID* arg1)
{
    const ADDRINT start = query_region_base((ADDRINT)arg1);
    const BOOL isReadableAddr = (start != UNKNOWN_ADDR && start != 0) && PIN_CheckReadAccess(arg1);
    return isReadableAddr;
}

// 猜参数类型
std::wstring paramToStr(VOID *arg1)
{
    if (arg1 == NULL) {
        return L"0";
    }
    std::wstringstream ss;

    if (!isValidReadPtr(arg1)) {
        // single value
        ss << std::hex << (arg1)
            << " = "
            << std::dec << ((size_t)arg1);
        return ss.str();
    }
    // possible pointer:
    ss << "ptr " << std::hex << (arg1);
    //
    // Check if UNICODE_STRING
    //
    typedef struct _T_UNICODE_STRING {
        uint16_t Length;
        uint16_t MaximumLength;
        wchar_t* Buffer;
    } T_UNICODE_STRING;

    T_UNICODE_STRING* unicodeS = reinterpret_cast<T_UNICODE_STRING*>(arg1);

    const size_t kMaxStr = 300;

    if (PIN_CheckReadAccess(&unicodeS->Buffer) 
        && (unicodeS->MaximumLength < kMaxStr) && (unicodeS->Length <= unicodeS->MaximumLength)// check if the length makes sense
        && isValidReadPtr(unicodeS->Buffer))
    {
        const size_t aLen = util::getAsciiLen(reinterpret_cast<char*>(unicodeS->Buffer), 2); // take minimal sample of ASCII string
        if (aLen == 1) {
            // Must be wide string
            size_t wLen = util::getAsciiLenW(unicodeS->Buffer, unicodeS->MaximumLength);
            if (wLen >= 1) {
                if ((unicodeS->Length / sizeof(wchar_t)) == wLen && unicodeS->MaximumLength >= unicodeS->Length) { // An extra check, just to make sure
                    ss << " -> ";
                    ss << "U\"" << unicodeS->Buffer << "\""; // Just made the U up to denote a UNICODE_STRING
                    return ss.str();
                }
            }
        }
    }

    bool isString = false;
    const char* val = reinterpret_cast<char*>(arg1);
    size_t len = util::getAsciiLen(val, kMaxStr);
    if (len > 0) {
        ss << " -> ";
    }
    if (len == 1) { // Possible wideString
        wchar_t* val = reinterpret_cast<wchar_t*>(arg1);
        size_t wLen = util::getAsciiLenW(val, kMaxStr);
        if (wLen >= len) {
            ss << "L\"" << val << "\"";
            isString = true;
        }
    }
    else if (len > 1) { // ASCII string
        ss << "\"" << val << "\"";
        isString = true;
    }
    if (!isString) {
        ss << " -> {";
        ss << util::hexdump(reinterpret_cast<const uint8_t*>(val), m_Settings.hexdumpSize);
        ss << "}";
    }
    return ss.str();
}

VOID _LogFunctionArgs(const ADDRINT Address, const CHAR *name, uint32_t argCount, VOID *arg1, VOID *arg2, VOID *arg3, VOID *arg4, VOID *arg5, VOID *arg6, VOID *arg7, VOID *arg8, VOID *arg9, VOID *arg10, VOID* arg11)
{
    if (isWatchedAddress(Address) == WatchedType::NOT_WATCHED) return;

    const size_t argsMax = LOGGED_ARGS_MAX;
    VOID* args[argsMax] = { arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11 };
    std::wstringstream ss;
    ss << name << ":\n";
    for (size_t i = 0; i < argCount && i < argsMax; i++) {
        ss << "\tArg[" << i << "] = ";
        ss << paramToStr(args[i]);
        ss << "\n";
    }

    std::wstring argsLineW = ss.str();
    std::string s(argsLineW.begin(), argsLineW.end());
    traceLog.logLine(s);
}

VOID LogFunctionArgs(const ADDRINT Address, CHAR *name, uint32_t argCount, VOID *arg1, VOID *arg2, VOID *arg3, VOID *arg4, VOID *arg5, VOID *arg6, VOID *arg7, VOID *arg8, VOID *arg9, VOID *arg10, VOID* arg11)
{
    PinLocker locker;
    _LogFunctionArgs(Address, name, argCount, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11);
}

VOID MonitorFunctionArgs(IMG Image, const WFuncInfo &funcInfo)
{
    const size_t argsMax = LOGGED_ARGS_MAX;
    const CHAR* fName = funcInfo.funcName.c_str();
    size_t argNum = funcInfo.paramCount;
    if (argNum > argsMax) argNum = argsMax;

    RTN funcRtn = find_by_unmangled_name(Image, fName);
    if (!RTN_Valid(funcRtn) || !funcInfo.isValid()) {
      std::cout
          << "[ERROR] find_by_unmangled_name failed , Invalid Function name? "
          << fName << std::endl;
        return;  // failed
    }

    LOG("Watch " + IMG_Name(Image) + " : " + fName + " [" + std::to_string(argNum) + "] " + static_cast<std::stringstream&>(std::stringstream() << std::hex << "0x" << RTN_Address(funcRtn)).str() + "\n");

    RTN_Open(funcRtn);

    RTN_InsertCall(funcRtn, IPOINT_BEFORE, AFUNPTR(LogFunctionArgs),
        IARG_RETURN_IP,
        IARG_ADDRINT, fName,
        IARG_UINT32, argNum,
        IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
        IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
        IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
        IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
        IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
        IARG_FUNCARG_ENTRYPOINT_VALUE, 5,
        IARG_FUNCARG_ENTRYPOINT_VALUE, 6,
        IARG_FUNCARG_ENTRYPOINT_VALUE, 7,
        IARG_FUNCARG_ENTRYPOINT_VALUE, 8,
        IARG_FUNCARG_ENTRYPOINT_VALUE, 9,
        IARG_FUNCARG_ENTRYPOINT_VALUE, 10,
        IARG_END
    );

    RTN_Close(funcRtn);
}

/* ===================================================================== */
// Instrumentation callbacks
/* ===================================================================== */
VOID InstrumentInstruction(INS ins, VOID *v)
{
    ADDRINT Address = INS_Address(ins);
    
    // Debug , Very poor performance
    //LOG("Trace " + static_cast<std::stringstream&>(std::stringstream() << std::hex << "0x" << Address).str() + " " + INS_Disassemble(ins) + "\n");
    //

#ifndef _WIN64
    if (INS_IsFarCall(ins)) {
        return;
    }

    if (INS_IsFarJump(ins)) {
        return;
    }
#endif // !_WIN64


    if (m_Settings.stopOffsets.size() > 0) {
        INS_InsertCall(
            ins,
            IPOINT_BEFORE, (AFUNPTR)PauseAtOffset,
            IARG_CONST_CONTEXT,
            IARG_END
        );
    }
    if (util::isStrEqualI(INS_Mnemonic(ins), "cpuid")) {
        INS_InsertCall(
            ins,
            IPOINT_BEFORE, (AFUNPTR)CpuidCalled,
            IARG_CONST_CONTEXT,
            IARG_END
        );
#ifdef USE_ANTIVM
        // ANTIVM: Register Function instrumentation needed for AntiVm
        if (m_Settings.antivm) {
            INS_InsertCall(
                ins,
                IPOINT_BEFORE, (AFUNPTR)AntiVm::CpuidCheck,
                IARG_CONST_CONTEXT,
                IARG_END
            );
        }
#endif
    }

    if (m_Settings.traceINT) {
        if (INS_IsInterrupt(ins)) {
            INS_InsertCall(
                ins,
                IPOINT_BEFORE, (AFUNPTR)InterruptCalled,
                IARG_CONST_CONTEXT,
                IARG_END
            );
        }
    }

    if (INS_IsRDTSC(ins)) {
        if (m_Settings.traceRDTSC) {
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)RdtscCalled, IARG_CONST_CONTEXT,
                IARG_END);

            INS_InsertCall(
                ins,
                IPOINT_AFTER, (AFUNPTR)AlterRdtscValueEdx,
                IARG_CONST_CONTEXT,
                IARG_RETURN_REGS,
                REG_GDX,
                IARG_END);

            INS_InsertCall(ins,
                IPOINT_AFTER, (AFUNPTR)AlterRdtscValueEax,
                IARG_CONST_CONTEXT,
                IARG_RETURN_REGS,
                REG_GAX,
                IARG_END);
        }
    }

    if (INS_IsControlFlow(ins) || INS_IsFarJump(ins)) {
        const BOOL isIndirect = INS_IsRet(ins);
        INS_InsertCall(
            ins,
            IPOINT_BEFORE, (AFUNPTR)SaveTransitions,
            IARG_INST_PTR, // AddrFrom 
            IARG_BRANCH_TARGET_ADDR, // AddrTo
            IARG_BOOL, isIndirect,
            IARG_CONST_CONTEXT,
            IARG_END
        );

    }
#ifdef USE_ANTIDEBUG
    // ANTIDEBUG: memory read instrumentation
    
    ////////////////////////////////////
    // If AntiDebug level is Standard
    ////////////////////////////////////
    if (m_Settings.antidebug != ANTIDEBUG_DISABLED) {

#ifdef _WIN64
        const char* POPF_MNEM = "popfq";
#else
        const char* POPF_MNEM = "popfd";
#endif
        if (util::isStrEqualI(INS_Mnemonic(ins), POPF_MNEM))
        {
            INS_InsertCall(
                ins,
                IPOINT_BEFORE, (AFUNPTR)AntiDbg::FlagsCheck,
                IARG_CONST_CONTEXT,
                IARG_THREAD_ID,
                IARG_END
            );

            INS_InsertCall(
                ins,
                IPOINT_AFTER, (AFUNPTR)AntiDbg::FlagsCheck_after,
                IARG_CONST_CONTEXT,
                IARG_THREAD_ID,
                IARG_INST_PTR,
                IARG_END
            );
        }
        
        if (INS_IsInterrupt(ins)) { // INS_IsValidForIpointAfter 一般都是return false,也就是Interrupt不能IPOINT_AFTER
            INS_InsertCall(
                ins,
                IPOINT_BEFORE, (AFUNPTR)AntiDbg::InterruptCheck,
                IARG_CONTEXT,
                IARG_END
            );
        }
        
        ////////////////////////////////////
        // If AntiDebug level is Deep
        ////////////////////////////////////
        // Deep目前多了个检测0xCC断点
        if (m_Settings.antidebug >= ANTIDEBUG_DEEP) {
            // Check all comparison for 0xCC byte (anti stepinto/stepover checks)
            const UINT32 opIdx = 1;
            if (INS_Opcode(ins) == XED_ICLASS_CMP 
                && INS_OperandCount(ins) >= (opIdx + 1) 
                && INS_OperandIsImmediate(ins, opIdx)
                && INS_OperandWidth(ins, opIdx) == (sizeof(UINT8)*8))
            {
                UINT64 imm = INS_OperandImmediate(ins, opIdx);
                INS_InsertCall(
                    ins,
                    IPOINT_BEFORE, (AFUNPTR)AntiDbg::WatchCompareSoftBrk,
                    IARG_INST_PTR,
                    IARG_UINT64, imm,
                    IARG_END);
            }
        }
    }
#endif
}

/* ===================================================================== */

VOID HookNtDelayExecution(const CHAR* name, UINT64* sleepTimePtr)
{
    PinLocker locker;

    if (PIN_CheckReadAccess(sleepTimePtr)) {

        INT64 sleepVal = (m_Settings.sleepTime != 0) ? (m_Settings.sleepTime * 10000) : 1;
        sleepVal = -(sleepVal);
        std::stringstream ss;
        ss << "\t"<< name <<" hooked. Overwriting DelayInterval: " << std::hex << (*sleepTimePtr) << " -> " << sleepVal << std::endl;
        traceLog.logLine(ss.str());
        (*sleepTimePtr) = sleepVal;
    }
}

/* ===================================================================== */


VOID ImageLoad(IMG Image, VOID *v)
{
    PinLocker locker;
    const std::string dllName = util::getDllName(IMG_Name(Image));

    pInfo.addModule(Image);
    for (size_t i = 0; i < m_Settings.funcWatch.funcs.size(); i++) {
        if (util::iequals(dllName, m_Settings.funcWatch.funcs[i].dllName)) {
            MonitorFunctionArgs(Image, m_Settings.funcWatch.funcs[i]);
        }
    }
    if (m_Settings.hookSleep) {
        const std::string dllName = util::getDllName(IMG_Name(Image));
        if (util::iequals(dllName, "ntdll")) {
            const CHAR *SLEEP = "NtDelayExecution";
            RTN sleepRtn = find_by_unmangled_name(Image, SLEEP);
            if (RTN_Valid(sleepRtn)) {
                RTN_Open(sleepRtn);
                RTN_InsertCall(sleepRtn, IPOINT_BEFORE, (AFUNPTR)HookNtDelayExecution, //Sleep的时间是由配置决定的
                    IARG_PTR, SLEEP,
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 1, 
                    IARG_END);
                RTN_Close(sleepRtn);
            }
        }
    }
#ifdef USE_ANTIDEBUG
    // ANTIDEBUG: Register Function instrumentation needed for AntiDebug
    if (m_Settings.antidebug != ANTIDEBUG_DISABLED) {
        // Register functions
        AntiDbg::MonitorAntiDbgFunctions(Image);
    }
#endif
#ifdef USE_ANTIVM
    // ANTIVM: Register Function instrumentation needed for AntiVm
    if (m_Settings.antivm) {
        // Register functions
        AntiVm::MonitorAntiVmFunctions(Image);
    }
#endif
}

static void OnCtxChange(THREADID threadIndex,
    CONTEXT_CHANGE_REASON reason,
    const CONTEXT *ctxtFrom,
    CONTEXT *ctxtTo,
    INT32 info,
    VOID *v)
{
    if (ctxtTo == NULL || ctxtFrom == NULL) return;

    PinLocker locker;

    const ADDRINT addrFrom = (ADDRINT)PIN_GetContextReg(ctxtFrom, REG_INST_PTR);
    const ADDRINT addrTo = (ADDRINT)PIN_GetContextReg(ctxtTo, REG_INST_PTR);
    //std::cout << "Get Exception In Application " << "addrFrom " << std::hex << addrFrom << " " << "addrTo " << addrTo << std::endl;
    _SaveTransitions(addrFrom, addrTo, FALSE);
}

/*!
* The main procedure of the tool.
* This function is called when the application image is loaded but not yet started.
* @param[in]   argc            total number of elements in the argv array
* @param[in]   argv            array of command line arguments,
*                              including pin -t <toolname> -- ...
*/
time_t tTraceStart;
int main(int argc, char* argv[])
{
    time(&tTraceStart);
    // Initialize PIN library. Print help message if -h(elp) is specified
    // in the command line or the command line is invalid 

    if (PIN_Init(argc, argv))
    {
        return Usage();
    }

    std::string app_name = KnobModuleName.Value();
    if (app_name.length() == 0) { // 默认是主程序,可以用-m参数指定DLL模块
        // init App Name:
        for (int i = 1; i < (argc - 1); i++) {
            if (strcmp(argv[i], "--") == 0) {
                app_name = argv[i + 1];
                break;
            }
        }
    }

    LOG("Get app_name " + app_name + "\n");
    pInfo.init(app_name);

    // select mode in which symbols should be initialized
    SYMBOL_INFO_MODE mode = EXPORT_SYMBOLS; // 如果要记录调用的操作系统的API的话,DEBUG符号没意义,导出符号就足够了
    if (m_Settings.useDebugSym) {
        LOG("Using debug symbols (if available)\n");
        mode = DEBUG_OR_EXPORT_SYMBOLS;
    }
    PIN_InitSymbolsAlt(mode);

    if (KnobStopOffsets.Enabled()) {
        std::string stopOffsetsFile = KnobStopOffsets.ValueString();
        if (stopOffsetsFile.length()) {
            const size_t loaded = Settings::loadOffsetsList(stopOffsetsFile, m_Settings.stopOffsets);
            LOG("Loaded " + std::to_string(loaded) + " stop offsets\n");
        }
    }
    if (KnobExcludedListFile.Enabled()) {
        std::string excludedList = KnobExcludedListFile.ValueString(); // 命令行参数-x指定 一般是excluded.txt
        if (excludedList.length()) {
            m_Settings.excludedFuncs.loadList(excludedList.c_str());
            LOG("Excluded " + std::to_string(m_Settings.excludedFuncs.funcs.size()) + " functions\n");
        }
    }

    if (KnobWatchListFile.Enabled()) {
        std::string watchListFile = KnobWatchListFile.ValueString(); // 命令行参数-b指定   一般是params.txt
        if (watchListFile.length()) {
            m_Settings.funcWatch.loadList(watchListFile.c_str(), &m_Settings.excludedFuncs);
            LOG("Watch " + std::to_string(m_Settings.funcWatch.funcs.size()) + " functions\n");
            LOG("Watch " + std::to_string(m_Settings.funcWatch.syscalls.size()) + " syscalls\n");
        }
    }

    if (KnobSyscallsTable.Enabled()) {
        std::string syscallsTableFile = KnobSyscallsTable.ValueString(); // 命令行参数-l指定 一般是syscalls.txt
        if (syscallsTableFile.length()) {
            m_Settings.syscallsTable.load(syscallsTableFile);
            LOG("SyscallTable size: " + std::to_string(m_Settings.syscallsTable.count()) + '\n');
        }
    }

    // init output file:
    traceLog.init(KnobOutputFile.Value(), m_Settings.shortLogging);

    // Register function to be called for every loaded module
    IMG_AddInstrumentFunction(ImageLoad, NULL);

    // Register function to be called before every instruction
    INS_AddInstrumentFunction(InstrumentInstruction, NULL);
#ifdef USE_ANTIDEBUG
    // ANTIDEBUG: collect some info on thread start
    if (m_Settings.antidebug != ANTIDEBUG_DISABLED) {
        PIN_AddThreadStartFunction(AntiDbg::WatchThreadStart, 0);
    }
#endif
    if (m_Settings.traceSYSCALL) {
        // Register function to be called before every syscall instruction
        // (i.e., syscall, sysenter, int 2Eh)
        //PIN_AddSyscallEntryFunction(SyscallCalled, NULL);
    }

    // KiUserExceptionDispatcher etc.
    PIN_AddContextChangeFunction(OnCtxChange, NULL);

    clearFlags();



    {
#define DECLSPEC_ALIGN(x)   __declspec(align(x))
#define DECLSPEC_NOINITALL __declspec(no_init_all)
#ifdef _WIN64
        typedef struct DECLSPEC_ALIGN(16) _M128A {
            unsigned __int64 Low;
            __int64 High;
        } M128A, * PM128A;
        typedef struct DECLSPEC_ALIGN(16) DECLSPEC_NOINITALL _CONTEXT {

            //
            // Register parameter home addresses.
            //
            // N.B. These fields are for convience - they could be used to extend the
            //      context record in the future.
            //

            unsigned __int64 P1Home;
            unsigned __int64 P2Home;
            unsigned __int64 P3Home;
            unsigned __int64 P4Home;
            unsigned __int64 P5Home;
            unsigned __int64 P6Home;

            //
            // Control flags.
            //

            __int32 ContextFlags;
            __int32 MxCsr;

            //
            // Segment Registers and processor flags.
            //

            short   SegCs;
            short   SegDs;
            short   SegEs;
            short   SegFs;
            short   SegGs;
            short   SegSs;
            unsigned int EFlags;

            //
            // Debug registers
            //

            unsigned __int64 Dr0;
            unsigned __int64 Dr1;
            unsigned __int64 Dr2;
            unsigned __int64 Dr3;
            unsigned __int64 Dr6;
            unsigned __int64 Dr7;

            //
            // Integer registers.
            //

            unsigned __int64 Rax;
            unsigned __int64 Rcx;
            unsigned __int64 Rdx;
            unsigned __int64 Rbx;
            unsigned __int64 Rsp;
            unsigned __int64 Rbp;
            unsigned __int64 Rsi;
            unsigned __int64 Rdi;
            unsigned __int64 R8;
            unsigned __int64 R9;
            unsigned __int64 R10;
            unsigned __int64 R11;
            unsigned __int64 R12;
            unsigned __int64 R13;
            unsigned __int64 R14;
            unsigned __int64 R15;

            //
            // Program counter.
            //

            unsigned __int64 Rip;

            //
            // Floating point state.
            //

            union {
                struct {
                    M128A Header[2];
                    M128A Legacy[8];
                    M128A Xmm0;
                    M128A Xmm1;
                    M128A Xmm2;
                    M128A Xmm3;
                    M128A Xmm4;
                    M128A Xmm5;
                    M128A Xmm6;
                    M128A Xmm7;
                    M128A Xmm8;
                    M128A Xmm9;
                    M128A Xmm10;
                    M128A Xmm11;
                    M128A Xmm12;
                    M128A Xmm13;
                    M128A Xmm14;
                    M128A Xmm15;
                } DUMMYSTRUCTNAME;
            } DUMMYUNIONNAME;

            //
            // Vector registers.
            //

            M128A VectorRegister[26];
            unsigned __int64 VectorControl;

            //
            // Special debug control registers.
            //

            unsigned __int64 DebugControl;
            unsigned __int64 LastBranchToRip;
            unsigned __int64 LastBranchFromRip;
            unsigned __int64 LastExceptionToRip;
            unsigned __int64 LastExceptionFromRip;
        } MYCONTEXT, * PMYCONTEXT;
#else
        typedef struct _FLOATING_SAVE_AREA {
            unsigned int   ControlWord;
            unsigned int   StatusWord;
            unsigned int   TagWord;
            unsigned int   ErrorOffset;
            unsigned int   ErrorSelector;
            unsigned int   DataOffset;
            unsigned int   DataSelector;
            unsigned char    RegisterArea[80];
            unsigned int   Spare0;
        } FLOATING_SAVE_AREA;
        typedef struct DECLSPEC_NOINITALL _CONTEXT {

            //
            // The flags values within this flag control the contents of
            // a CONTEXT record.
            //
            // If the context record is used as an input parameter, then
            // for each portion of the context record controlled by a flag
            // whose value is set, it is assumed that that portion of the
            // context record contains valid context. If the context record
            // is being used to modify a threads context, then only that
            // portion of the threads context will be modified.
            //
            // If the context record is used as an IN OUT parameter to capture
            // the context of a thread, then only those portions of the thread's
            // context corresponding to set flags will be returned.
            //
            // The context record is never used as an OUT only parameter.
            //

            unsigned int ContextFlags;

            //
            // This section is specified/returned if CONTEXT_DEBUG_REGISTERS is
            // set in ContextFlags.  Note that CONTEXT_DEBUG_REGISTERS is NOT
            // included in CONTEXT_FULL.
            //

            unsigned int   Dr0;
            unsigned int   Dr1;
            unsigned int   Dr2;
            unsigned int   Dr3;
            unsigned int   Dr6;
            unsigned int   Dr7;

            //
            // This section is specified/returned if the
            // ContextFlags word contians the flag CONTEXT_FLOATING_POINT.
            //

            FLOATING_SAVE_AREA FloatSave;

            //
            // This section is specified/returned if the
            // ContextFlags word contians the flag CONTEXT_SEGMENTS.
            //

            unsigned int   SegGs;
            unsigned int   SegFs;
            unsigned int   SegEs;
            unsigned int   SegDs;

            //
            // This section is specified/returned if the
            // ContextFlags word contians the flag CONTEXT_INTEGER.
            //

            unsigned int   Edi;
            unsigned int   Esi;
            unsigned int   Ebx;
            unsigned int   Edx;
            unsigned int   Ecx;
            unsigned int   Eax;

            //
            // This section is specified/returned if the
            // ContextFlags word contians the flag CONTEXT_CONTROL.
            //

            unsigned int   Ebp;
            unsigned int   Eip;
            unsigned int   SegCs;              // MUST BE SANITIZED
            unsigned int   EFlags;             // MUST BE SANITIZED
            unsigned int   Esp;
            unsigned int   SegSs;

            //
            // This section is specified/returned if the ContextFlags word
            // contains the flag CONTEXT_EXTENDED_REGISTERS.
            // The format and contexts are processor specific
            //

            unsigned char    ExtendedRegisters[512];

        } MYCONTEXT;

        typedef MYCONTEXT* PMYCONTEXT;
#endif

#ifndef _WIN64
        typedef struct _EXCEPTION_RECORD {
            unsigned int    ExceptionCode;
            unsigned int ExceptionFlags;
            unsigned int ExceptionRecord;
            unsigned int ExceptionAddress;
            unsigned int NumberParameters;
            unsigned int ExceptionInformation[15];
        } EXCEPTION_RECORD, * PEXCEPTION_RECORD;
#else
        typedef struct _EXCEPTION_RECORD {
            unsigned int    ExceptionCode;
            unsigned int ExceptionFlags;
            unsigned __int64 ExceptionRecord;
            unsigned __int64 ExceptionAddress;
            unsigned int NumberParameters;
            unsigned int __unusedAlignment;
            unsigned __int64 ExceptionInformation[15];
        } EXCEPTION_RECORD, * PEXCEPTION_RECORD;
#endif

        typedef EXCEPTION_RECORD* PEXCEPTION_RECORD;


        //
        // Typedef for pointer returned by exception_info()
        //

        typedef struct _EXCEPTION_POINTERS {
            PEXCEPTION_RECORD ExceptionRecord;
            PMYCONTEXT ContextRecord;
        } EXCEPTION_POINTERS, * PEXCEPTION_POINTERS;

        PinLocker Locker;
        // 这里一般是捕获Pintool内部的异常
        LOG("Register InternalExceptionHandler\n");
        PIN_AddInternalExceptionHandler([](THREADID threadIndex, EXCEPTION_INFO* pExceptInfo,
            PHYSICAL_CONTEXT* pPhysCtxt, VOID* v)->EXCEPT_HANDLING_RESULT {
                EXCEPTION_CODE ExceptionCode = PIN_GetExceptionCode(pExceptInfo);
                LOG("Exception In Pintool " + pExceptInfo->GetCodeAsString() + "\n");
                return EHR_UNHANDLED;
            }, 0);
        LOG("Register ContextChangeFunction\n");

        // 接管应用程序的异常
        PIN_AddContextChangeFunction([](THREADID threadIndex, CONTEXT_CHANGE_REASON reason, const CONTEXT* from, CONTEXT* to, INT32 info, VOID* v)
            {
                auto TranslateReasonToString = [=](CONTEXT_CHANGE_REASON reason)->std::string {
                    switch (reason) {
                    case CONTEXT_CHANGE_REASON_FATALSIGNAL:
                        return "CONTEXT_CHANGE_REASON_FATALSIGNAL";
                    case CONTEXT_CHANGE_REASON_SIGNAL:
                        return "CONTEXT_CHANGE_REASON_SIGNAL";
                    case CONTEXT_CHANGE_REASON_SIGRETURN:
                        return "CONTEXT_CHANGE_REASON_SIGRETURN";
                    case CONTEXT_CHANGE_REASON_APC:
                        return "CONTEXT_CHANGE_REASON_APC";
                    case CONTEXT_CHANGE_REASON_EXCEPTION:
                        return "CONTEXT_CHANGE_REASON_EXCEPTION";
                    case CONTEXT_CHANGE_REASON_CALLBACK:
                        return "CONTEXT_CHANGE_REASON_CALLBACK";
                    }
                    };
                LOG("ContextChange reason " + TranslateReasonToString(reason)+"\n");


                if (reason != CONTEXT_CHANGE_REASON_EXCEPTION) { // If the caught exception is not a Windows exception, return.
                    return;
                }

                LOG("Exception Code " + static_cast<std::stringstream&>(std::stringstream() << std::hex << "0x" << info).str() + "\n");

                LOG("From Context \n");
                printContext(from,4);
                LOG("To Context \n");
                printContext(to,4);

                switch (info)
                {
                case 0x80000003:
                    break;
                case 0xc0000005:
                    break;
                default:
                    break;
                }
            }, 0);
    }
    std::cerr << "===============================================" << std::endl;
    std::cerr << "This application is instrumented by " << TOOL_NAME << " v." << VERSION << std::endl;
    std::cerr << "Tracing module: " << app_name << std::endl;
    if (!KnobOutputFile.Value().empty())
    {
        std::cerr << "See file " << KnobOutputFile.Value() << " for analysis results" << std::endl;
    }
    std::cerr << "See file pintool.log" << " for develop logs" << std::endl;
    std::cerr << "===============================================" << std::endl;

    // Helper with performence monitor
    PIN_AddFiniFunction([](INT32 code, VOID* v) {
        LOG("Application Exit , Code " + std::to_string(code)+"\n");
        time_t tNow;
        time(&tNow);
        double elapsed = difftime(tNow, tTraceStart);
        LOG("Trace Cost " + std::to_string(elapsed) + "\n");
        }, nullptr);

    // Start the program, never returns
    // Jit Mode
    PIN_StartProgram();
    return 0;
}

/* ===================================================================== */
/* eof */
/* ===================================================================== */
