#include "Anti.h"
#include "win/my_paths.h"
#include <Windows.h>

typedef DWORD PROCESSINFOCLASS;
typedef LONG NTSTATUS;

typedef struct _PEB
{
    BOOLEAN InheritedAddressSpace;      // These four fields cannot change unless the
    BOOLEAN ReadImageFileExecOptions;   //
    BOOLEAN BeingDebugged;              //
    BOOLEAN SpareBool;                  //
    HANDLE Mutant;                      // INITIAL_PEB structure is also updated.

    PVOID ImageBaseAddress;
    PVOID Ldr;
    PVOID ProcessParameters;
    PVOID SubSystemData;
    PVOID ProcessHeap;
    PVOID FastPebLock;
    PVOID FastPebLockRoutine;
    PVOID FastPebUnlockRoutine;
    ULONG EnvironmentUpdateCount;
    PVOID KernelCallbackTable;
    HANDLE SystemReserved;
    PVOID  AtlThunkSListPtr32;
    PVOID FreeList;
    ULONG TlsExpansionCounter;
    PVOID TlsBitmap;
    ULONG TlsBitmapBits[2];         // relates to TLS_MINIMUM_AVAILABLE
    PVOID ReadOnlySharedMemoryBase;
    PVOID ReadOnlySharedMemoryHeap;
    PVOID* ReadOnlyStaticServerData;
    PVOID AnsiCodePageData;
    PVOID OemCodePageData;
    PVOID UnicodeCaseTableData;

    //
    // Useful information for LdrpInitialize

    ULONG NumberOfProcessors;
    ULONG NtGlobalFlag;
//[...]

} PEB, * PPEB;

//---

PPEB NTAPI RtlGetCurrentPeb(VOID);

NTSTATUS
NTAPI
NtSetInformationProcess(
    _In_ HANDLE ProcessHandle,
    _In_ PROCESSINFOCLASS ProcessInformationClass,
    _In_ PVOID ProcessInformation,
    _In_ ULONG ProcessInformationLength
);

//---

bool clearProcessDebugFlags()
{
    // ProcessDebugFlags
    const int ProcessDebugFlags = 0x1f;

    auto _NtSetInformationProcess = reinterpret_cast<decltype(&NtSetInformationProcess)>(GetProcAddress(GetModuleHandleA("ntdll"), "NtSetInformationProcess"));
    if (!_NtSetInformationProcess) {
        return false;
    }
    // Other Vars
    NTSTATUS Status;
    DWORD NoDebugInherit = 1;

    Status = _NtSetInformationProcess(GetCurrentProcess(), ProcessDebugFlags, &NoDebugInherit, sizeof(DWORD));
    return (Status == 0);
}

bool clearGlobalFlag()
{
    auto _RtlGetCurrentPeb = reinterpret_cast<decltype(&RtlGetCurrentPeb)>(GetProcAddress(GetModuleHandleA("ntdll"), "RtlGetCurrentPeb"));
    if (!_RtlGetCurrentPeb) {
        return false;
    }
    
    PEB* peb = _RtlGetCurrentPeb();
    peb->NtGlobalFlag = 0;
    return true;
}

int clearFlags()
{
    int cleared = 0;
    if (clearProcessDebugFlags()) {
        cleared++;
    }
    if (clearGlobalFlag()) {
        cleared++;
    }
    return cleared;
}
