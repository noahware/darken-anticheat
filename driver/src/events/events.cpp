#include "events.hpp"
#include "../log.hpp"

#include <ntifs.h>
#include <vector.hpp>
#include <mutex.hpp>
#include <string.hpp>
#include <crt.hpp>

#include "flatbuffers/flatbuffers.h"
#include "event_generated.h"

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
    cstd::vector<event_entry>* event_queue_ = nullptr;

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

        const auto name_str = (full_image_name && full_image_name->Buffer && full_image_name->Length > 0)
            ? cstd::to_string(cstd::wstring_view{ full_image_name->Buffer, full_image_name->Length / sizeof(wchar_t) })
            : cstd::string{};

        const auto estimated = 48 + name_str.size();
        flatbuffers::FlatBufferBuilder fbb(estimated);

        auto name_offset = fbb.CreateString(name_str.data(), name_str.size());
        auto load = Anticheat::CreateKernelModuleLoad(
            fbb,
            base,
            size,
            name_offset
        );
        fbb.Finish(load);

        event_entry entry;
        entry.type = Anticheat::EventBody_KernelModuleLoad;
        entry.data = cstd::vector<uint8_t>(fbb.GetBufferPointer(), fbb.GetSize());

        {
            cstd::lock_guard<cstd::mutex> guard(lock_);
            event_queue_->push_back(cstd::move(entry));
        }

        KeSetEvent(event_object_, IO_NO_INCREMENT, FALSE);

        DBG_LOG("module loaded: %wZ @ %p (size: 0x%x)\n",
            full_image_name, image_info->ImageBase, size);
    }
}

namespace events
{
    NTSTATUS init()
    {
        event_queue_ = new cstd::vector<event_entry>();

        OBJECT_ATTRIBUTES oa;
        InitializeObjectAttributes(&oa, nullptr, OBJ_KERNEL_HANDLE, nullptr, nullptr);

        auto status = ZwCreateEvent(&event_handle_, EVENT_ALL_ACCESS, &oa, SynchronizationEvent, FALSE);

        if (!NT_SUCCESS(status))
        {
            DBG_LOG("ZwCreateEvent failed: 0x%x\n", status);
            return status;
        }

        status = ObReferenceObjectByHandle(
            event_handle_,
            EVENT_ALL_ACCESS,
            *ExEventObjectType,
            KernelMode,
            reinterpret_cast<PVOID*>(&event_object_),
            nullptr
        );

        if (!NT_SUCCESS(status))
        {
            DBG_LOG("ObReferenceObjectByHandle failed: 0x%x\n", status);
            ZwClose(event_handle_);
            event_handle_ = nullptr;
            return status;
        }

        status = PsSetLoadImageNotifyRoutine(on_image_load);

        if (!NT_SUCCESS(status))
        {
            DBG_LOG("PsSetLoadImageNotifyRoutine failed: 0x%x\n", status);
            ObDereferenceObject(event_object_);
            event_object_ = nullptr;
            ZwClose(event_handle_);
            event_handle_ = nullptr;
            return status;
        }

        DBG_LOG("event system initialized\n");
        return STATUS_SUCCESS;
    }

    void cleanup()
    {
        PsRemoveLoadImageNotifyRoutine(on_image_load);

        if (event_object_)
        {
            ObDereferenceObject(event_object_);
            event_object_ = nullptr;
        }

        if (event_handle_)
        {
            ZwClose(event_handle_);
            event_handle_ = nullptr;
        }

        delete event_queue_;
        event_queue_ = nullptr;

        DBG_LOG("event system cleaned up\n");
    }

    NTSTATUS get_event_handle(PIRP irp)
    {
        const auto* stack = IoGetCurrentIrpStackLocation(irp);
        const auto output_capacity = stack->Parameters.DeviceIoControl.OutputBufferLength;

        if (output_capacity < sizeof(HANDLE))
        {
            irp->IoStatus.Status = STATUS_BUFFER_TOO_SMALL;
            irp->IoStatus.Information = 0;
            IoCompleteRequest(irp, IO_NO_INCREMENT);
            return STATUS_BUFFER_TOO_SMALL;
        }

        HANDLE user_handle = nullptr;

        const auto status = ObOpenObjectByPointer(
            event_object_,
            0,
            nullptr,
            EVENT_ALL_ACCESS,
            *ExEventObjectType,
            UserMode,
            &user_handle
        );

        if (!NT_SUCCESS(status))
        {
            DBG_LOG("ObOpenObjectByPointer failed: 0x%x\n", status);
            irp->IoStatus.Status = status;
            irp->IoStatus.Information = 0;
            IoCompleteRequest(irp, IO_NO_INCREMENT);
            return status;
        }

        *static_cast<HANDLE*>(irp->AssociatedIrp.SystemBuffer) = user_handle;

        irp->IoStatus.Status = STATUS_SUCCESS;
        irp->IoStatus.Information = sizeof(HANDLE);
        IoCompleteRequest(irp, IO_NO_INCREMENT);
        return STATUS_SUCCESS;
    }

    NTSTATUS drain(PIRP irp)
    {
        const auto* stack = IoGetCurrentIrpStackLocation(irp);
        const auto output_capacity = stack->Parameters.DeviceIoControl.OutputBufferLength;

        cstd::vector<event_entry> local_events;

        {
            cstd::lock_guard<cstd::mutex> guard(lock_);
            local_events = cstd::move(*event_queue_);
            *event_queue_ = cstd::vector<event_entry>();
            KeClearEvent(event_object_);
        }

        const auto estimated = 48 + local_events.size() * 96;
        flatbuffers::FlatBufferBuilder fbb(estimated);

        cstd::vector<flatbuffers::Offset<Anticheat::Event>> event_offsets;

        for (auto& entry : local_events)
        {
            if (entry.type != Anticheat::EventBody_KernelModuleLoad)
            {
                continue;
            }

            const auto* load = flatbuffers::GetRoot<Anticheat::KernelModuleLoad>(entry.data.data());
            auto name_offset = fbb.CreateString(load->name()->c_str(), load->name()->size());
            auto load_offset = Anticheat::CreateKernelModuleLoad(
                fbb, load->base_address(), load->size(), name_offset
            );
            auto event_offset = Anticheat::CreateEvent(fbb, Anticheat::EventBody_KernelModuleLoad, load_offset.Union());
            event_offsets.push_back(event_offset);
        }

        auto events_vec = fbb.CreateVector(event_offsets.data(), event_offsets.size());
        auto batch = Anticheat::CreateEventBatch(fbb, events_vec);
        fbb.Finish(batch);

        const auto response_size = fbb.GetSize();

        if (response_size > output_capacity)
        {
            irp->IoStatus.Status = STATUS_BUFFER_TOO_SMALL;
            irp->IoStatus.Information = 0;
            IoCompleteRequest(irp, IO_NO_INCREMENT);
            return STATUS_BUFFER_TOO_SMALL;
        }

        cstd::crt::memcpy(irp->AssociatedIrp.SystemBuffer, fbb.GetBufferPointer(), response_size);

        irp->IoStatus.Status = STATUS_SUCCESS;
        irp->IoStatus.Information = response_size;
        IoCompleteRequest(irp, IO_NO_INCREMENT);
        return STATUS_SUCCESS;
    }
}
