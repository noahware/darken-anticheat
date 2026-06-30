#include "table.hpp"
#include "../state/protected_process.hpp"
#include "../krnl/krnl.hpp"
#include "../krnl/list.hpp"
#include "../krnl/types.hpp"
#include "../util/rva.hpp"
#include "../log.hpp"

#include <ntifs.h>

#include "handle.hpp"
#include "flatbuffers/flatbuffers.h"
#include "handle_strip_generated.h"

#define PROCESS_QUERY_LIMITED_INFORMATION (0x1000)

extern "C" POBJECT_TYPE ObGetObjectType(void* object);

using ex_enum_handle_table_callback_fn = BOOLEAN(*)(_HANDLE_TABLE* table, _HANDLE_TABLE_ENTRY* entry, HANDLE handle, void* context);
using ex_unlock_handle_table_entry_fn = void(*)(_HANDLE_TABLE* table, _HANDLE_TABLE_ENTRY* entry);
using ex_enum_handle_table_fn = BOOLEAN(*)(
    _HANDLE_TABLE* table,
    ex_enum_handle_table_callback_fn callback,
    void* context,
    HANDLE* handle
);

struct handle_strip_info
{
    uint64_t source_process_id;
    uint64_t target_process_id;
    uint32_t access;
};

namespace
{
    ex_enum_handle_table_fn ex_enum_handle_table = nullptr;
    ex_unlock_handle_table_entry_fn ex_unlock_handle_table_entry = nullptr;
    PLIST_ENTRY handle_table_list_head = nullptr;

    BOOLEAN enum_callback(_HANDLE_TABLE* const table, _HANDLE_TABLE_ENTRY* const entry, [[maybe_unused]] HANDLE handle, void* context)
    {
        if (!entry || !entry->ObjectPointerBits || (entry->GrantedAccessBits & blacklisted_proc_handle_access) == 0 || table->UniqueProcessId == 4)
        {
            ex_unlock_handle_table_entry(table, entry);
            return FALSE;
        }

        auto& handle_infos = *static_cast<cstd::vector<handle_strip_info>*>(context);

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

        handle_infos.push_back(handle_strip_info{
	        .source_process_id = table->UniqueProcessId, .target_process_id = target_process_id,
	        .access = entry->GrantedAccessBits
        });

        entry->GrantedAccessBits &= ~blacklisted_proc_handle_access;

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

    ex_unlock_handle_table_entry = reinterpret_cast<ex_unlock_handle_table_entry_fn>(resolve_rip_relative(unlock_ref, 1, 5));

    const auto handle_table_list_ref = krnl::nt->signature_scan("4C 8B 35 ? ? ? ? B9");

    if (!handle_table_list_ref)
    {
        DBG_LOG("failed to find HandleTableListHead\n");
        return nt_status::not_implemented();
    }

    handle_table_list_head = reinterpret_cast<PLIST_ENTRY>(resolve_rip_relative(handle_table_list_ref, 3, 7));

    DBG_LOG("ExEnumHandleTable: %p, ExUnlockHandleTableEntry: %p, HandleTableListHead: %p\n",
            ex_enum_handle_table, ex_unlock_handle_table_entry, handle_table_list_head);

    return nt_status::success();
}

cstd::vector<uint8_t> handle::tbl::strip()
{
    if (!ex_enum_handle_table || !handle_table_list_head)
    {
        return { };
    }

    cstd::vector<handle_strip_info> handle_infos;

    const krnl::list_range<_HANDLE_TABLE, &_HANDLE_TABLE::HandleTableList> handle_tables(handle_table_list_head);

    for (_HANDLE_TABLE& table : handle_tables)
    {
    	ex_enum_handle_table(&table, enum_callback, &handle_infos, nullptr);
    }

    flatbuffers::FlatBufferBuilder fbb(handle_infos.size() * 32);
    cstd::vector<flatbuffers::Offset<Anticheat::StrippedHandleInfo>> handle_offsets;

    for (const auto& info : handle_infos)
    {
        handle_offsets.push_back(
            Anticheat::CreateStrippedHandleInfo(fbb, info.target_process_id, info.source_process_id, info.access)
        );
    }

    auto handles_vec = fbb.CreateVector(handle_offsets.data(), handle_offsets.size());
    auto result = Anticheat::CreateHandleStripResult(fbb, handles_vec);
    fbb.Finish(result);

    const auto* buf = fbb.GetBufferPointer();
    const auto size = fbb.GetSize();

    return cstd::vector<uint8_t>(buf, size);
}
