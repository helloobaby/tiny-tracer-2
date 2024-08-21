#pragma once


typedef unsigned long       DWORD;
typedef unsigned char       BYTE;
typedef unsigned short      WORD;
typedef float               FLOAT;
typedef FLOAT* PFLOAT;
typedef BYTE* PBYTE;
typedef BYTE* LPBYTE;
typedef int* PINT;
typedef int* LPINT;
typedef WORD* PWORD;
typedef WORD* LPWORD;
typedef long* LPLONG;
typedef DWORD* PDWORD;
typedef DWORD* LPDWORD;
typedef void* LPVOID;
typedef void* LPCVOID;

typedef int                 INT;
typedef unsigned int        UINT;
typedef unsigned int* PUINT;
typedef void* PVOID;

#if defined(_WIN64)
typedef __int64 INT_PTR, * PINT_PTR;
typedef unsigned __int64 UINT_PTR, * PUINT_PTR;

typedef __int64 LONG_PTR, * PLONG_PTR;
typedef unsigned __int64 ULONG_PTR, * PULONG_PTR;

#define __int3264   __int64

#else
typedef  int INT_PTR, * PINT_PTR;
typedef  unsigned int UINT_PTR, * PUINT_PTR;

typedef  long LONG_PTR, * PLONG_PTR;
typedef  unsigned long ULONG_PTR, * PULONG_PTR;

#define __int3264   __int32

#endif
typedef ULONG_PTR SIZE_T, * PSIZE_T;
typedef LONG_PTR SSIZE_T, * PSSIZE_T;

typedef struct _MEMORY_BASIC_INFORMATION {
    PVOID BaseAddress;
    PVOID AllocationBase;
    DWORD AllocationProtect;
#if defined (_WIN64)
    WORD   PartitionId;
#endif
    SIZE_T RegionSize;
    DWORD State;
    DWORD Protect;
    DWORD Type;
} MEMORY_BASIC_INFORMATION, * PMEMORY_BASIC_INFORMATION;

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

using _VirtualQuery = unsigned __int64
(_stdcall*)(
    LPCVOID lpAddress,
    PMEMORY_BASIC_INFORMATION lpBuffer,
    SIZE_T dwLength
    );
