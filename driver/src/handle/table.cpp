#include "table.hpp"
#include "../state/protected_process.hpp"
#include "../krnl/krnl.hpp"
#include "../krnl/list.hpp"
#include "../krnl/types.hpp"
#include "../log.hpp"

#include <ntifs.h>

#define PROCESS_QUERY_LIMITED_INFORMATION (0x1000)

extern "C" POBJECT_TYPE ObGetObjectType(void* object);

using ex_enum_handle_table_callback_fn = BOOLEAN(*)(_HANDLE_TABLE* table, _HANDLE_TABLE_ENTRY* entry, HANDLE handle, void* context);

using ex_enum_handle_table_fn = BOOLEAN(*)(
    _HANDLE_TABLE* table,
    ex_enum_handle_table_callback_fn callback,
    void* context,
    HANDLE* handle
);

using ex_unlock_handle_table_entry_fn = void(*)(_HANDLE_TABLE* table, _HANDLE_TABLE_ENTRY* entry);

namespace
{
    ex_enum_handle_table_fn ex_enum_handle_table = nullptr;
    ex_unlock_handle_table_entry_fn ex_unlock_handle_table_entry = nullptr;
    PLIST_ENTRY handle_table_list_head = nullptr;

    BOOLEAN enum_callback([[maybe_unused]] _HANDLE_TABLE* const table, _HANDLE_TABLE_ENTRY* const entry, [[maybe_unused]] HANDLE handle, [[maybe_unused]] void* context)
    {
        if (!entry || !entry->ObjectPointerBits)
        {
            ex_unlock_handle_table_entry(table, entry);
            return FALSE;
        }

        const auto object_header = reinterpret_cast<_OBJECT_HEADER*>(
            0xffff000000000000 | (static_cast<uint64_t>(entry->ObjectPointerBits) << 4)
        );
        const auto object = reinterpret_cast<void*>(&object_header->Body);

        if (ObGetObjectType(object) != *PsProcessType)
        {
            ex_unlock_handle_table_entry(table, entry);
            return FALSE;
        }

        const auto target_process = static_cast<PEPROCESS>(object);
        const auto target_process_id = reinterpret_cast<protected_process_t::id_type>(PsGetProcessId(target_process));

        if (!protected_process_t::find(target_process_id))
        {
            ex_unlock_handle_table_entry(table, entry);
            return FALSE;
        }

        DBG_LOG("stripping handle to protected process 0x%llx (access=0x%lx)\n",
                target_process_id, entry->GrantedAccessBits);

        constexpr ULONG access_mask = (1u << 25) - 1;
        constexpr ULONG new_access = SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION;
        auto* const access_dword = reinterpret_cast<volatile LONG*>(reinterpret_cast<uint8_t*>(entry) + 0x8);
        LONG old_val, new_val;

        do
        {
            old_val = *access_dword;
            new_val = (old_val & ~static_cast<LONG>(access_mask)) | static_cast<LONG>(new_access);
        }
        while (_InterlockedCompareExchange(access_dword, new_val, old_val) != old_val);

        ex_unlock_handle_table_entry(table, entry);

        return FALSE;
    }
}

nt_status handle::tbl::init()
{
    const auto enum_fn = krnl::nt->find_export("ExEnumHandleTable");

    if (!enum_fn)
    {
        DBG_LOG("failed to resolve ExEnumHandleTable\n");
        return nt_status::not_implemented();
    }

    ex_enum_handle_table = reinterpret_cast<ex_enum_handle_table_fn>(enum_fn);

    const auto unlock_ref = krnl::nt->signature_scan("E8 ? ? ? ? 85 ED 0F 84 ? ? ? ? 41 BD");

    if (!unlock_ref)
    {
        DBG_LOG("failed to find ExUnlockHandleTableEntry\n");
        return nt_status::not_implemented();
    }

    const auto unlock_rva = *reinterpret_cast<const int32_t*>(unlock_ref + 1);
    ex_unlock_handle_table_entry = reinterpret_cast<ex_unlock_handle_table_entry_fn>(unlock_ref + 5 + unlock_rva);

    const auto handle_table_list_ref = krnl::nt->signature_scan("4C 8B 35 ? ? ? ? B9");

    if (!handle_table_list_ref)
    {
        DBG_LOG("failed to find HandleTableListHead\n");
        return nt_status::not_implemented();
    }

    const auto rva = *reinterpret_cast<const int32_t*>(handle_table_list_ref + 3);
    handle_table_list_head = reinterpret_cast<PLIST_ENTRY>(handle_table_list_ref + 7 + rva);

    DBG_LOG("ExEnumHandleTable: %p, ExUnlockHandleTableEntry: %p, HandleTableListHead: %p\n",
            ex_enum_handle_table, ex_unlock_handle_table_entry, handle_table_list_head);

    return nt_status::success();
}

void handle::tbl::strip()
{
    if (!ex_enum_handle_table || !handle_table_list_head)
    {
        return;
    }

    const krnl::list_range<_HANDLE_TABLE, &_HANDLE_TABLE::HandleTableList> handle_tables(handle_table_list_head);

    for (_HANDLE_TABLE& table : handle_tables)
    {
    	ex_enum_handle_table(&table, enum_callback, nullptr, nullptr);
    }
}

