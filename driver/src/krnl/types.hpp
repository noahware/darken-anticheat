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

struct system_thread_information
{
    LARGE_INTEGER kernel_time;
    LARGE_INTEGER user_time;
    LARGE_INTEGER create_time;
    ULONG wait_time;
    PVOID start_address;
    CLIENT_ID client_id;
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
