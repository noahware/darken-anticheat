#pragma once
#include <ntdef.h>

//0xa0 bytes (sizeof)
struct _KLDR_DATA_TABLE_ENTRY
{
    struct _LIST_ENTRY InLoadOrderLinks;                                    //0x0
    VOID* ExceptionTable;                                                   //0x10
    ULONG ExceptionTableSize;                                               //0x18
    VOID* GpValue;                                                          //0x20
    struct _NON_PAGED_DEBUG_INFO* NonPagedDebugInfo;                        //0x28
    VOID* DllBase;                                                          //0x30
    VOID* EntryPoint;                                                       //0x38
    ULONG SizeOfImage;                                                      //0x40
    struct _UNICODE_STRING FullDllName;                                     //0x48
    struct _UNICODE_STRING BaseDllName;                                     //0x58
    ULONG Flags;                                                            //0x68
    USHORT LoadCount;                                                       //0x6c
    union
    {
        USHORT SignatureLevel : 4;                                            //0x6e
        USHORT SignatureType : 3;                                             //0x6e
        USHORT Unused : 9;                                                    //0x6e
        USHORT EntireField;                                                 //0x6e
    } u1;                                                                   //0x6e
    VOID* SectionPointer;                                                   //0x70
    ULONG CheckSum;                                                         //0x78
    ULONG CoverageSectionSize;                                              //0x7c
    VOID* CoverageSection;                                                  //0x80
    VOID* LoadedImports;                                                    //0x88
    VOID* Spare;                                                            //0x90
    ULONG SizeOfImageNotRounded;                                            //0x98
    ULONG TimeDateStamp;                                                    //0x9c
};

//0x8 bytes (sizeof)
struct _MI_ACTIVE_PFN
{
    union
    {
        struct
        {
            ULONGLONG Tradable : 1;                                           //0x0
            ULONGLONG NonPagedBuddy : 43;                                     //0x0
        } Leaf;                                                             //0x0
        struct
        {
            ULONGLONG Tradable : 1;                                           //0x0
            ULONGLONG WsleAge : 3;                                            //0x0
            ULONGLONG OldestWsleLeafEntries : 10;                             //0x0
            ULONGLONG OldestWsleLeafAge : 3;                                  //0x0
            ULONGLONG NonPagedBuddy : 43;                                     //0x0
        } PageTable;                                                        //0x0
        ULONGLONG EntireActiveField;                                        //0x0
    };
};

//0x8 bytes (sizeof)
struct _MMPTE
{
    union
    {
        ULONGLONG Long;                                                     //0x0
        volatile ULONGLONG VolatileLong;                                    //0x0
    } u;                                                                    //0x0
};

//0x8 bytes (sizeof)
struct _MIPFNBLINK
{
    union
    {
        struct
        {
            ULONGLONG Blink : 40;                                             //0x0
            ULONGLONG NodeBlinkLow : 19;                                      //0x0
            ULONGLONG TbFlushStamp : 3;                                       //0x0
            ULONGLONG PageBlinkDeleteBit : 1;                                 //0x0
            ULONGLONG PageBlinkLockBit : 1;                                   //0x0
            ULONGLONG ShareCount : 62;                                        //0x0
            ULONGLONG PageShareCountDeleteBit : 1;                            //0x0
            ULONGLONG PageShareCountLockBit : 1;                              //0x0
        };
        ULONGLONG EntireField;                                              //0x0
        volatile LONGLONG Lock;                                             //0x0
        struct
        {
            ULONGLONG LockNotUsed : 62;                                       //0x0
            ULONGLONG DeleteBit : 1;                                          //0x0
            ULONGLONG LockBit : 1;                                            //0x0
        };
    };
};

//0x1 bytes (sizeof)
struct _MMPFNENTRY1
{
    UCHAR PageLocation : 3;                                                   //0x0
    UCHAR WriteInProgress : 1;                                                //0x0
    UCHAR Modified : 1;                                                       //0x0
    UCHAR ReadInProgress : 1;                                                 //0x0
    UCHAR CacheAttribute : 2;                                                 //0x0
};

//0x1 bytes (sizeof)
struct _MMPFNENTRY3
{
    UCHAR Priority : 3;                                                       //0x0
    UCHAR OnProtectedStandby : 1;                                             //0x0
    UCHAR InPageError : 1;                                                    //0x0
    UCHAR SystemChargedPage : 1;                                              //0x0
    UCHAR RemovalRequested : 1;                                               //0x0
    UCHAR ParityError : 1;                                                    //0x0
};

//0x4 bytes (sizeof)
struct _MI_PFN_ULONG5
{
    union
    {
        ULONG EntireField;                                                  //0x0
        struct
        {
            ULONG NodeBlinkHigh : 21;                                         //0x0
            ULONG NodeFlinkMiddle : 11;                                       //0x0
        } StandbyList;                                                      //0x0
        struct
        {
            UCHAR ModifiedListBucketIndex : 4;                                //0x0
        } MappedPageList;                                                   //0x0
        struct
        {
            UCHAR AnchorLargePageSize : 2;                                    //0x0
            UCHAR Spare0 : 6;                                                 //0x0
            UCHAR Spare1 : 8;                                                 //0x1
            USHORT Spare2;                                                  //0x2
        } Active;                                                           //0x0
    };
};

//0x30 bytes (sizeof)
struct _MMPFN
{
    union
    {
        struct _LIST_ENTRY ListEntry;                                       //0x0
        struct _RTL_BALANCED_NODE TreeNode;                                 //0x0
        struct
        {
            union
            {
                struct _SINGLE_LIST_ENTRY NextSlistPfn;                     //0x0
                VOID* Next;                                                 //0x0
                ULONGLONG Flink : 40;                                         //0x0
                ULONGLONG NodeFlinkLow : 24;                                  //0x0
                struct _MI_ACTIVE_PFN Active;                               //0x0
            } u1;                                                           //0x0
            union
            {
                struct _MMPTE* PteAddress;                                  //0x8
                ULONGLONG PteLong;                                          //0x8
            };
            struct _MMPTE OriginalPte;                                      //0x10
        };
    };
    struct _MIPFNBLINK u2;                                                  //0x18
    union
    {
        struct
        {
            USHORT ReferenceCount;                                          //0x20
            struct _MMPFNENTRY1 e1;                                         //0x22
        };
        struct
        {
            struct _MMPFNENTRY3 e3;                                         //0x23
            struct
            {
                USHORT ReferenceCount;                                          //0x20
            } e2;                                                               //0x20
        };
        struct
        {
            ULONG EntireField;                                              //0x20
        } e4;                                                               //0x20
    } u3;                                                                   //0x20
    struct _MI_PFN_ULONG5 u5;                                               //0x24
    union
    {
        ULONGLONG PteFrame : 40;                                              //0x28
        ULONGLONG ResidentPage : 1;                                           //0x28
        ULONGLONG Unused1 : 1;                                                //0x28
        ULONGLONG Unused2 : 1;                                                //0x28
        ULONGLONG Partition : 10;                                             //0x28
        ULONGLONG FileOnly : 1;                                               //0x28
        ULONGLONG PfnExists : 1;                                              //0x28
        ULONGLONG NodeFlinkHigh : 5;                                          //0x28
        ULONGLONG PageIdentity : 3;                                           //0x28
        ULONGLONG PrototypePte : 1;                                           //0x28
        ULONGLONG EntireField;                                              //0x28
    } u4;                                                                   //0x28
};

//0x8 bytes (sizeof)
struct _EX_PUSH_LOCK
{
    union
    {
        struct
        {
            ULONGLONG Locked : 1;                                             //0x0
            ULONGLONG Waiting : 1;                                            //0x0
            ULONGLONG Waking : 1;                                             //0x0
            ULONGLONG MultipleShared : 1;                                     //0x0
            ULONGLONG Shared : 60;                                            //0x0
        };
        ULONGLONG Value;                                                    //0x0
        VOID* Ptr;                                                          //0x0
    };
};

//0x40 bytes (sizeof)
struct _HANDLE_TABLE_FREE_LIST
{
    struct _EX_PUSH_LOCK FreeListLock;                                      //0x0
    union _HANDLE_TABLE_ENTRY* FirstFreeHandleEntry;                        //0x8
    union _HANDLE_TABLE_ENTRY* LastFreeHandleEntry;                         //0x10
    LONG HandleCount;                                                       //0x18
    ULONG HighWaterMark;                                                    //0x1c
};

//0x80 bytes (sizeof)
struct _HANDLE_TABLE
{
    ULONG NextHandleNeedingPool;                                            //0x0
    LONG ExtraInfoPages;                                                    //0x4
    volatile ULONGLONG TableCode;                                           //0x8
    struct _EPROCESS* QuotaProcess;                                         //0x10
    struct _LIST_ENTRY HandleTableList;                                     //0x18
    ULONG UniqueProcessId;                                                  //0x28
    union
    {
        ULONG Flags;                                                        //0x2c
        struct
        {
            UCHAR StrictFIFO : 1;                                             //0x2c
            UCHAR EnableHandleExceptions : 1;                                 //0x2c
            UCHAR Rundown : 1;                                                //0x2c
            UCHAR Duplicated : 1;                                             //0x2c
            UCHAR RaiseUMExceptionOnInvalidHandleClose : 1;                   //0x2c
        };
    };
    struct _EX_PUSH_LOCK HandleContentionEvent;                             //0x30
    struct _EX_PUSH_LOCK HandleTableLock;                                   //0x38
    union
    {
        struct _HANDLE_TABLE_FREE_LIST FreeLists[1];                        //0x40
        struct
        {
            UCHAR ActualEntry[32];                                          //0x40
            struct _HANDLE_TRACE_DEBUG_INFO* DebugInfo;                     //0x60
        };
    };
};

//0x8 bytes (sizeof)
struct _EXHANDLE
{
    union
    {
        struct
        {
            ULONG TagBits : 2;                                                //0x0
            ULONG Index : 30;                                                 //0x0
        };
        VOID* GenericHandleOverlay;                                         //0x0
        ULONGLONG Value;                                                    //0x0
    };
};

//0x10 bytes (sizeof)
union _HANDLE_TABLE_ENTRY
{
    volatile LONGLONG VolatileLowValue;                                     //0x0
    LONGLONG LowValue;                                                       //0x0

    struct
    {
        struct _HANDLE_TABLE_ENTRY_INFO* volatile InfoTable;                 //0x0
        union
        {
            LONGLONG HighValue;                                              //0x8
            union _HANDLE_TABLE_ENTRY* NextFreeHandleEntry;                  //0x8
            struct _EXHANDLE LeafHandleValue;                                //0x8
        };
    };

    LONGLONG RefCountField;                                                  //0x0

    struct
    {
        ULONGLONG Unlocked : 1;                                              //0x0
        ULONGLONG RefCnt : 16;                                               //0x0
        ULONGLONG Attributes : 3;                                            //0x0
        ULONGLONG ObjectPointerBits : 44;                                    //0x0
        ULONG GrantedAccessBits : 25;                                        //0x8
        ULONG NoRightsUpgrade : 1;                                           //0x8
        ULONG Spare1 : 6;                                                    //0x8
        ULONG Spare2;                                                        //0xc
    };
};

//0x38 bytes (sizeof)
struct _OBJECT_HEADER
{
    LONGLONG PointerCount;                                                  //0x0
    union
    {
        LONGLONG HandleCount;                                               //0x8
        VOID* NextToFree;                                                   //0x8
    };
    struct _EX_PUSH_LOCK Lock;                                              //0x10
    UCHAR TypeIndex;                                                        //0x18
    union
    {
        UCHAR TraceFlags;                                                   //0x19
        struct
        {
            UCHAR DbgRefTrace : 1;                                            //0x19
            UCHAR DbgTracePermanent : 1;                                      //0x19
        };
    };
    UCHAR InfoMask;                                                         //0x1a
    union
    {
        UCHAR Flags;                                                        //0x1b
        struct
        {
            UCHAR NewObject : 1;                                              //0x1b
            UCHAR KernelObject : 1;                                           //0x1b
            UCHAR KernelOnlyAccess : 1;                                       //0x1b
            UCHAR ExclusiveObject : 1;                                        //0x1b
            UCHAR PermanentObject : 1;                                        //0x1b
            UCHAR DefaultSecurityQuota : 1;                                   //0x1b
            UCHAR SingleHandleEntry : 1;                                      //0x1b
            UCHAR DeletedInline : 1;                                          //0x1b
        };
    };
    ULONG Reserved;                                                         //0x1c
    union
    {
        struct _OBJECT_CREATE_INFORMATION* ObjectCreateInfo;                //0x20
        VOID* QuotaBlockCharged;                                            //0x20
    };
    VOID* SecurityDescriptor;                                               //0x28
    struct _QUAD Body;                                                      //0x30
};

struct machine_frame
{
    uint64_t rip;
    uint64_t cs;
    uint64_t rflags;
    uint64_t rsp;
    uint64_t ss;
};

//0xa8 bytes (sizeof)
struct _KAFFINITY_EX
{
    USHORT Count;                                                           //0x0
    USHORT Size;                                                            //0x2
    ULONG Reserved;                                                         //0x4
    ULONGLONG Bitmap[20];                                                   //0x8
};

struct system_thread_information
{
    LARGE_INTEGER kernel_time;
    LARGE_INTEGER user_time;
    LARGE_INTEGER create_time;
    ULONG wait_time;
    PVOID start_address;
    struct
    {
        HANDLE UniqueProcess;
        HANDLE UniqueThread;
    } client_id;
    LONG priority;
    LONG base_priority;
    ULONG context_switches;
    ULONG thread_state;
    ULONG wait_reason;
};

struct system_process_information
{
    ULONG next_entry_offset;
    ULONG number_of_threads;
    LARGE_INTEGER working_set_private_size;
    ULONG hard_fault_count;
    ULONG number_of_threads_high_watermark;
    ULONGLONG cycle_time;
    LARGE_INTEGER create_time;
    LARGE_INTEGER user_time;
    LARGE_INTEGER kernel_time;
    UNICODE_STRING image_name;
    LONG base_priority;
    HANDLE unique_process_id;
    HANDLE inherited_from_unique_process_id;
    ULONG handle_count;
    ULONG session_id;
    ULONG_PTR unique_process_key;
    SIZE_T peak_virtual_size;
    SIZE_T virtual_size;
    ULONG page_fault_count;
    SIZE_T peak_working_set_size;
    SIZE_T working_set_size;
    SIZE_T quota_peak_paged_pool_usage;
    SIZE_T quota_paged_pool_usage;
    SIZE_T quota_peak_non_paged_pool_usage;
    SIZE_T quota_non_paged_pool_usage;
    SIZE_T pagefile_usage;
    SIZE_T peak_pagefile_usage;
    SIZE_T private_page_count;
    LARGE_INTEGER read_operation_count;
    LARGE_INTEGER write_operation_count;
    LARGE_INTEGER other_operation_count;
    LARGE_INTEGER read_transfer_count;
    LARGE_INTEGER write_transfer_count;
    LARGE_INTEGER other_transfer_count;
    system_thread_information threads[1];
};
