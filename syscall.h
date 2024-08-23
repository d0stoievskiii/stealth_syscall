#pragma once

#include <windows.h>
#include <stdint.h>
#include <wchar.h>

typedef struct _UNICODE_STRING
{
    uint16_t Length;
    uint16_t MaximumLength;
    const wchar_t* Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

//https://www.vergiliusproject.com/kernels/x64/windows-10/21h2/_RTL_BALANCED_NODE
struct _RTL_BALANCED_NODE
{
    union
    {
        struct _RTL_BALANCED_NODE* Children[2];                             //0x0
        struct
        {
            struct _RTL_BALANCED_NODE* Left;                                //0x0
            struct _RTL_BALANCED_NODE* Right;                               //0x8
        };
    };
    union
    {
        struct
        {
            UCHAR Red:1;                                                    //0x10
            UCHAR Balance:2;                                                //0x10
        };
        ULONGLONG ParentValue;                                              //0x10
    };
}; 

//https://www.vergiliusproject.com/kernels/x64/windows-10/21h2/_LDR_DATA_TABLE_ENTRY
typedef struct _LDR_DATA_TABLE_ENTRY
{
    struct _LIST_ENTRY InLoadOrderLinks;                                    //0x0
    struct _LIST_ENTRY InMemoryOrderLinks;                                  //0x10
    struct _LIST_ENTRY InInitializationOrderLinks;                          //0x20
    VOID* DllBase;                                                          //0x30
    VOID* EntryPoint;                                                       //0x38
    ULONG SizeOfImage;                                                      //0x40
    struct _UNICODE_STRING FullDllName;                                     //0x48
    struct _UNICODE_STRING BaseDllName;                                     //0x58
    union
    {
        UCHAR FlagGroup[4];                                                 //0x68
        ULONG Flags;                                                        //0x68
        struct
        {
            ULONG PackagedBinary:1;                                         //0x68
            ULONG MarkedForRemoval:1;                                       //0x68
            ULONG ImageDll:1;                                               //0x68
            ULONG LoadNotificationsSent:1;                                  //0x68
            ULONG TelemetryEntryProcessed:1;                                //0x68
            ULONG ProcessStaticImport:1;                                    //0x68
            ULONG InLegacyLists:1;                                          //0x68
            ULONG InIndexes:1;                                              //0x68
            ULONG ShimDll:1;                                                //0x68
            ULONG InExceptionTable:1;                                       //0x68
            ULONG ReservedFlags1:2;                                         //0x68
            ULONG LoadInProgress:1;                                         //0x68
            ULONG LoadConfigProcessed:1;                                    //0x68
            ULONG EntryProcessed:1;                                         //0x68
            ULONG ProtectDelayLoad:1;                                       //0x68
            ULONG ReservedFlags3:2;                                         //0x68
            ULONG DontCallForThreads:1;                                     //0x68
            ULONG ProcessAttachCalled:1;                                    //0x68
            ULONG ProcessAttachFailed:1;                                    //0x68
            ULONG CorDeferredValidate:1;                                    //0x68
            ULONG CorImage:1;                                               //0x68
            ULONG DontRelocate:1;                                           //0x68
            ULONG CorILOnly:1;                                              //0x68
            ULONG ChpeImage:1;                                              //0x68
            ULONG ReservedFlags5:2;                                         //0x68
            ULONG Redirected:1;                                             //0x68
            ULONG ReservedFlags6:2;                                         //0x68
            ULONG CompatDatabaseProcessed:1;                                //0x68
        };
    };
    USHORT ObsoleteLoadCount;                                               //0x6c
    USHORT TlsIndex;                                                        //0x6e
    struct _LIST_ENTRY HashLinks;                                           //0x70
    ULONG TimeDateStamp;                                                    //0x80
    struct _ACTIVATION_CONTEXT* EntryPointActivationContext;                //0x88
    VOID* Lock;                                                             //0x90
    struct _LDR_DDAG_NODE* DdagNode;                                        //0x98
    struct _LIST_ENTRY NodeModuleLink;                                      //0xa0
    struct _LDRP_LOAD_CONTEXT* LoadContext;                                 //0xb0
    VOID* ParentDllBase;                                                    //0xb8
    VOID* SwitchBackContext;                                                //0xc0
    struct _RTL_BALANCED_NODE BaseAddressIndexNode;                         //0xc8
    struct _RTL_BALANCED_NODE MappingInfoIndexNode;                         //0xe0
    ULONGLONG OriginalBase;                                                 //0xf8
    union _LARGE_INTEGER LoadTime;                                          //0x100
    ULONG BaseNameHashValue;                                                //0x108
    enum _LDR_DLL_LOAD_REASON LoadReason;                                   //0x10c
    ULONG ImplicitPathOptions;                                              //0x110
    ULONG ReferenceCount;                                                   //0x114
    ULONG DependentLoadFlags;                                               //0x118
    UCHAR SigningLevel;                                                     //0x11c
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;



typedef ULONG_PTR QWORD;

#define MZ 0x5A4D
#define PE00 0x00004550

namespace syscall {

    uint8_t raw[] = {
        0x4C, 0x8B, 0xD1, //mov r10, rcx
        0xB8, 0x00, 0x00, 0x00, 0x00, //mov EAX, syscall_number
        0x0F, 0x05, //syscall
        0xC3 //return
    };

    inline PLDR_DATA_TABLE_ENTRY getLoadedModuleLinkedList() {
        QWORD peb = __readgsqword(0x60); //get the process evironment block -> https://www.vergiliusproject.com/kernels/x64/windows-10/22h2/_PEB
        peb = *(QWORD*)(peb+ 0x18); //get the pointer to the PEB_LDR_DATA
        peb = *(QWORD*)(peb + 0x10); //InLoadOrderModuleList List_Entry links to other list_entry structs that head the LDR_DATA_TABLE_ENTRYs we are after

        return (PLDR_DATA_TABLE_ENTRY)(peb);
    };

    inline uint64_t getModuleBase(const wchar_t* module) {
        PLDR_DATA_TABLE_ENTRY entry = getLoadedModuleLinkedList();

        while (entry->BaseDllName.Buffer != 0x0) {
            auto current = entry->BaseDllName.Buffer;

            uint64_t base = (uint64_t)entry->DllBase;
            entry = reinterpret_cast<PLDR_DATA_TABLE_ENTRY>(entry->InLoadOrderLinks.Flink);
            if (!base) continue;

            if (!wcscmp(current, module)) return base;
        }
        return { };
    }

    inline uint32_t getIndex(const wchar_t* module, const char* routine) {
        uint64_t moduleBase = getModuleBase(module);
        if (!moduleBase) {
            return 0;
        }

        //The first bytes of a PE file begin with the traditional MS-DOS header, called an IMAGE_DOS_HEADER.
        PIMAGE_DOS_HEADER dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(moduleBase);
        if (dos_header->e_magic != MZ) return 0; //The e_magic field (a WORD) needs to be set to the value 0x5A4D -> https://learn.microsoft.com/en-us/archive/msdn-magazine/2002/february/inside-windows-win32-portable-executable-file-format-in-detail

        //The IMAGE_NT_HEADERS structure is the primary location where specifics of the PE file are stored
        //Its offset is given by the e_lfanew field in the IMAGE_DOS_HEADER at the beginning of the file
        PIMAGE_NT_HEADERS64 nt_header = reinterpret_cast<PIMAGE_NT_HEADERS64>((uint8_t*)moduleBase + dos_header->e_lfanew);
        if (nt_header->Signature != PE00) return 0; //In a valid PE file, the Signature field is set to the value 0x00004550, which in ASCII is "PE00"

        //lets look for our syscall wrapper walking through the IMAGE_DATA_DIRECTORY array
        uint64_t exportVirtualAddress = nt_header->OptionalHeader.DataDirectory[0].VirtualAddress;
        if (!exportVirtualAddress) return 0;//null ptr

        //IMAGE_EXPORT_DIRECTORY heads the virtual address
        PIMAGE_EXPORT_DIRECTORY exportDir = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>((uint8_t*)moduleBase + exportVirtualAddress);

        uint32_t* addressFuncs = reinterpret_cast<uint32_t*>((uint8_t*)moduleBase + exportDir->AddressOfFunctions);
        uint32_t* addressNames = reinterpret_cast<uint32_t*>((uint8_t*)moduleBase + exportDir->AddressOfNames);
        uint16_t* addressNamesOrdinal = reinterpret_cast<uint16_t*>((uint8_t*)moduleBase + exportDir->AddressOfNameOrdinals);

        for (int i = 0; i < exportDir->NumberOfNames; i++) {
            char* curr = reinterpret_cast<char*>(moduleBase) + addressNames[i];

            if (!strcmp(curr, routine)) {
                return *reinterpret_cast<uint32_t*>((moduleBase + addressFuncs[addressNamesOrdinal[i]]) + 4);
            }
            //the index of the syscall(a int) happens to be the last 32 bits of the address of the function
        }

        return 0;
        //we failed
    }

    inline void* allocate_call(uint32_t idx) {
        void* mem = VirtualAlloc(0, sizeof(raw), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (mem) {
            memcpy(mem, raw, sizeof(raw));
            *(uint32_t*)((uint8_t*)mem + 4) = idx;
        }
        return mem;
    }
}