#include "Anti.h"
#include "win/my_paths.h"
#include <Windows.h>
#include <intrin.h>
#include <iostream>

typedef DWORD PROCESSINFOCLASS;
typedef LONG NTSTATUS;

#ifdef _WIN64
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
#else
typedef struct _PEB                                     // 111 elements, 0x480 bytes (sizeof) 
{
    /*0x000*/     UINT8        InheritedAddressSpace;
    /*0x001*/     UINT8        ReadImageFileExecOptions;
    /*0x002*/     UINT8        BeingDebugged;
    union                                                  // 2 elements, 0x1 bytes (sizeof)     
    {
        /*0x003*/         UINT8        BitField;
        struct                                             // 8 elements, 0x1 bytes (sizeof)     
        {
            /*0x003*/             UINT8        ImageUsesLargePages : 1;          // 0 BitPosition                      
            /*0x003*/             UINT8        IsProtectedProcess : 1;           // 1 BitPosition                      
            /*0x003*/             UINT8        IsImageDynamicallyRelocated : 1;  // 2 BitPosition                      
            /*0x003*/             UINT8        SkipPatchingUser32Forwarders : 1; // 3 BitPosition                      
            /*0x003*/             UINT8        IsPackagedProcess : 1;            // 4 BitPosition                      
            /*0x003*/             UINT8        IsAppContainer : 1;               // 5 BitPosition                      
            /*0x003*/             UINT8        IsProtectedProcessLight : 1;      // 6 BitPosition                      
            /*0x003*/             UINT8        IsLongPathAwareProcess : 1;       // 7 BitPosition                      
        };
    };
    /*0x004*/     ULONG32      Mutant;
    /*0x008*/     ULONG32      ImageBaseAddress;
    /*0x00C*/     ULONG32      Ldr;
    /*0x010*/     ULONG32      ProcessParameters;
    /*0x014*/     ULONG32      SubSystemData;
    /*0x018*/     ULONG32      ProcessHeap;
    /*0x01C*/     ULONG32      FastPebLock;
    /*0x020*/     ULONG32      AtlThunkSListPtr;
    /*0x024*/     ULONG32      IFEOKey;
    union                                                  // 2 elements, 0x4 bytes (sizeof)     
    {
        /*0x028*/         ULONG32      CrossProcessFlags;
        struct                                             // 9 elements, 0x4 bytes (sizeof)     
        {
            /*0x028*/             ULONG32      ProcessInJob : 1;                 // 0 BitPosition                      
            /*0x028*/             ULONG32      ProcessInitializing : 1;          // 1 BitPosition                      
            /*0x028*/             ULONG32      ProcessUsingVEH : 1;              // 2 BitPosition                      
            /*0x028*/             ULONG32      ProcessUsingVCH : 1;              // 3 BitPosition                      
            /*0x028*/             ULONG32      ProcessUsingFTH : 1;              // 4 BitPosition                      
            /*0x028*/             ULONG32      ProcessPreviouslyThrottled : 1;   // 5 BitPosition                      
            /*0x028*/             ULONG32      ProcessCurrentlyThrottled : 1;    // 6 BitPosition                      
            /*0x028*/             ULONG32      ProcessImagesHotPatched : 1;      // 7 BitPosition                      
            /*0x028*/             ULONG32      ReservedBits0 : 24;               // 8 BitPosition                      
        };
    };
    union                                                  // 2 elements, 0x4 bytes (sizeof)     
    {
        /*0x02C*/         ULONG32      KernelCallbackTable;
        /*0x02C*/         ULONG32      UserSharedInfoPtr;
    };
    /*0x030*/     ULONG32      SystemReserved;
    /*0x034*/     ULONG32      AtlThunkSListPtr32;
    /*0x038*/     ULONG32      ApiSetMap;
    /*0x03C*/     ULONG32      TlsExpansionCounter;
    /*0x040*/     ULONG32      TlsBitmap;
    /*0x044*/     ULONG32      TlsBitmapBits[2];
    /*0x04C*/     ULONG32      ReadOnlySharedMemoryBase;
    /*0x050*/     ULONG32      SharedData;
    /*0x054*/     ULONG32      ReadOnlyStaticServerData;
    /*0x058*/     ULONG32      AnsiCodePageData;
    /*0x05C*/     ULONG32      OemCodePageData;
    /*0x060*/     ULONG32      UnicodeCaseTableData;
    /*0x064*/     ULONG32      NumberOfProcessors;
    /*0x068*/     ULONG32      NtGlobalFlag;
}PEB, * PPEB;
#endif
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
#ifdef _WIN64
    auto _RtlGetCurrentPeb = reinterpret_cast<decltype(&RtlGetCurrentPeb)>(GetProcAddress(GetModuleHandleA("ntdll"), "RtlGetCurrentPeb"));
    if (!_RtlGetCurrentPeb) {
        return false;
    }
    PEB* peb = _RtlGetCurrentPeb();
#else // _WIN64
    BYTE* _teb32 = (BYTE*)__readfsdword(0x18);
    PEB* peb = (PEB*)(_teb32 + 0x30);
#endif
    peb->NtGlobalFlag = 0;
    return true;
}

int clearFlags()
{
    //std::cout << "clearFlags\n";
    int cleared = 0;
    if (clearProcessDebugFlags()) {
        cleared++;
    }
    if (clearGlobalFlag()) {
        cleared++;
    }
    return cleared;
}
