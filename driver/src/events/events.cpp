#include "events.hpp"
#include "../log.hpp"
#include "../krnl/modules.hpp"

#include <ntifs.h>

#include "../util/import.hpp"
#include <vector.hpp>
#include <mutex.hpp>
#include <string.hpp>
#include <crt.hpp>

#include "flatbuffers/flatbuffers.h"
#include "event_generated.h"
#include "../util/serialisation.hpp"

namespace
{
    struct event_entry
    {
        Anticheat::EventBody type;
        cstd::vector<uint8_t> data;
    };

    cstd::mutex lock_;
    HANDLE event_handle_ = nullptr;
    PKEVENT event_object_ = nullptr;
    cstd::vector<event_entry> event_queue_;

    void on_image_load(
        [[maybe_unused]] PUNICODE_STRING full_image_name,
        [[maybe_unused]] HANDLE process_id,
        PIMAGE_INFO image_info)
    {
        if (!image_info->SystemModeImage)
        {
            return;
        }

        const auto base = reinterpret_cast<uint64_t>(image_info->ImageBase);
        const auto size = static_cast<uint32_t>(image_info->ImageSize);
        const auto image = static_cast<portable_executable::image_t*>(image_info->ImageBase);
        const auto hash_result = krnl::hash_nonwritable_sections(image);

        const auto path_str = (full_image_name && full_image_name->Buffer && full_image_name->Length > 0)
            ? cstd::to_string(cstd::wstring_view{ full_image_name->Buffer, full_image_name->Length / sizeof(wchar_t) })
            : cstd::string{};

        const auto name_start = path_str.rfind('\\');
        const auto name_str = (name_start != cstd::string::npos)
            ? cstd::string(path_str.data() + name_start + 1, path_str.size() - name_start - 1)
            : path_str;

        flatbuffers::FlatBufferBuilder fbb;

        auto name_offset = fbb.CreateString(name_str.data(), name_str.size());
        auto path_offset = fbb.CreateString(path_str.data(), path_str.size());

        flatbuffers::Offset<flatbuffers::Vector<uint8_t>> hash_offset;

        if (hash_result)
        {
            hash_offset = fbb.CreateVector(
                hash_result.value().data(), crypto::sha256_size
            );
        }

        event_entry entry;
        entry.type = Anticheat::EventBody_KernelModuleLoad;
        entry.data = serialisation::serialise(
            fbb, serialisation::lift<Anticheat::CreateKernelModuleLoad>(),
            base, size, name_offset, hash_offset, path_offset
        );

        {
            cstd::lock_guard<cstd::mutex> guard(lock_);
            event_queue_.push_back(cstd::move(entry));
        }

        LIMPORT(KeSetEvent)(event_object_, IO_NO_INCREMENT, FALSE);

        DBG_LOG("module loaded: %wZ @ %p (size: 0x%x)\n",
            full_image_name, image_info->ImageBase, size);
    }
}

namespace events
{
    nt_status init()
    {
        OBJECT_ATTRIBUTES oa;
        InitializeObjectAttributes(&oa, nullptr, OBJ_KERNEL_HANDLE, nullptr, nullptr);

        nt_status status = LIMPORT(ZwCreateEvent)(&event_handle_, EVENT_ALL_ACCESS, &oa, SynchronizationEvent, FALSE);

        if (!status)
        {
            DBG_LOG("ZwCreateEvent failed: 0x%x\n", status.value());
            return status;
        }

        status = LIMPORT(ObReferenceObjectByHandle)(
            event_handle_,
            EVENT_ALL_ACCESS,
            *ExEventObjectType,
            KernelMode,
            reinterpret_cast<PVOID*>(&event_object_),
            nullptr
        );

        if (!status)
        {
            DBG_LOG("ObReferenceObjectByHandle failed: 0x%x\n", status.value());
            LIMPORT(ZwClose)(event_handle_);
            event_handle_ = nullptr;
            return status;
        }

        status = LIMPORT(PsSetLoadImageNotifyRoutine)(on_image_load);

        if (!status)
        {
            DBG_LOG("PsSetLoadImageNotifyRoutine failed: 0x%x\n", status.value());
            LIMPORT(ObDereferenceObject)(event_object_);
            event_object_ = nullptr;
            LIMPORT(ZwClose)(event_handle_);
            event_handle_ = nullptr;
            return status;
        }

        DBG_LOG("event system initialized\n");
        return nt_status::success();
    }

    void cleanup()
    {
        LIMPORT(PsRemoveLoadImageNotifyRoutine)(on_image_load);

        if (event_object_)
        {
            LIMPORT(ObDereferenceObject)(event_object_);
            event_object_ = nullptr;
        }

        if (event_handle_)
        {
            LIMPORT(ZwClose)(event_handle_);
            event_handle_ = nullptr;
        }

        event_queue_.clear();

        DBG_LOG("event system cleaned up\n");
    }

    nt_status get_event_handle(PIRP irp)
    {
        const auto* stack = LIMPORT(IoGetCurrentIrpStackLocation)(irp);
        const auto output_capacity = stack->Parameters.DeviceIoControl.OutputBufferLength;

        if (output_capacity < sizeof(HANDLE))
        {
            irp->IoStatus.Status = nt_status::buffer_too_small();
            irp->IoStatus.Information = 0;
            LIMPORT(IoCompleteRequest)(irp, IO_NO_INCREMENT);
            return nt_status::buffer_too_small();
        }

        HANDLE user_handle = nullptr;

        const nt_status status = LIMPORT(ObOpenObjectByPointer)(
            event_object_,
            0,
            nullptr,
            EVENT_ALL_ACCESS,
            *ExEventObjectType,
            UserMode,
            &user_handle
        );

        if (!status)
        {
            DBG_LOG("ObOpenObjectByPointer failed: 0x%x\n", status.value());
            irp->IoStatus.Status = status;
            irp->IoStatus.Information = 0;
            LIMPORT(IoCompleteRequest)(irp, IO_NO_INCREMENT);
            return status;
        }

        *static_cast<HANDLE*>(irp->AssociatedIrp.SystemBuffer) = user_handle;

        irp->IoStatus.Status = nt_status::success();
        irp->IoStatus.Information = sizeof(HANDLE);
        LIMPORT(IoCompleteRequest)(irp, IO_NO_INCREMENT);
        return nt_status::success();
    }

    nt_status drain(PIRP irp)
    {
        const auto* stack = LIMPORT(IoGetCurrentIrpStackLocation)(irp);
        const auto output_capacity = stack->Parameters.DeviceIoControl.OutputBufferLength;

        cstd::vector<event_entry> local_events;

        {
            cstd::lock_guard<cstd::mutex> guard(lock_);
            local_events = cstd::move(event_queue_);
            event_queue_ = cstd::vector<event_entry>();
            LIMPORT(KeClearEvent)(event_object_);
        }

        flatbuffers::FlatBufferBuilder fbb;

        cstd::vector<flatbuffers::Offset<Anticheat::Event>> event_offsets;

        for (auto& entry : local_events)
        {
            if (entry.type != Anticheat::EventBody_KernelModuleLoad)
            {
                continue;
            }

            const auto* load = serialisation::deserialise<Anticheat::KernelModuleLoad>(entry.data.data());
            auto name_offset = fbb.CreateString(load->name()->c_str(), load->name()->size());

            flatbuffers::Offset<flatbuffers::String> path_offset;
            if (load->full_path())
            {
                path_offset = fbb.CreateString(load->full_path()->c_str(), load->full_path()->size());
            }

            flatbuffers::Offset<flatbuffers::Vector<uint8_t>> hash_offset;

            if (load->hash())
            {
                hash_offset = fbb.CreateVector(load->hash()->data(), load->hash()->size());
            }

            auto load_offset = Anticheat::CreateKernelModuleLoad(
                fbb, load->base_address(), load->size(), name_offset, hash_offset, path_offset
            );
            auto event_offset = Anticheat::CreateEvent(fbb, Anticheat::EventBody_KernelModuleLoad, load_offset.Union());
            event_offsets.push_back(event_offset);
        }

        auto events_vec = fbb.CreateVector(event_offsets.data(), event_offsets.size());
        auto batch_data = serialisation::serialise(fbb, serialisation::lift<Anticheat::CreateEventBatch>(), events_vec);

        const auto response_size = batch_data.size();

        if (response_size > output_capacity)
        {
            irp->IoStatus.Status = nt_status::buffer_too_small();
            irp->IoStatus.Information = 0;
            LIMPORT(IoCompleteRequest)(irp, IO_NO_INCREMENT);
            return nt_status::buffer_too_small();
        }

        cstd::crt::memcpy(irp->AssociatedIrp.SystemBuffer, batch_data.data(), response_size);

        irp->IoStatus.Status = nt_status::success();
        irp->IoStatus.Information = response_size;
        LIMPORT(IoCompleteRequest)(irp, IO_NO_INCREMENT);
        return nt_status::success();
    }
}
