#include <ntifs.h>
#include <string.hpp>
#include <portable_executable/image.hpp>

#include "log.hpp"
#include "emu/emu.hpp"
#include "krnl/krnl.hpp"
#include "krnl/list.hpp"
#include "krnl/types.hpp"
#include "ioctl/ioctl.hpp"
#include "events/events.hpp"
#include <driver/ioctl.h>

static PDEVICE_OBJECT g_device_object = nullptr;

[[nodiscard]] static portable_executable::image_t* get_ntoskrnl(const PDRIVER_OBJECT driver_object)
{
	const auto curr = static_cast<_KLDR_DATA_TABLE_ENTRY*>(driver_object->DriverSection);

	auto it = krnl::loaded_module_list_entry_t(
		&curr->InLoadOrderLinks
	);

	++it;
	++it;

	return static_cast<portable_executable::image_t*>(it->DllBase);
}

[[nodiscard]] static uint8_t* get_mm_pfn_database()
{
	const auto sig = krnl::nt->signature_scan("48 B8 ? ? ? ? ? ? ? ? 48 8B 04 D0 48 C1 E0");

	if (!sig)
	{
		return nullptr;
	}

	return *reinterpret_cast<uint8_t**>(sig + 2) - 8;
}

static NTSTATUS dispatch_create_close([[maybe_unused]] PDEVICE_OBJECT device, PIRP irp)
{
	irp->IoStatus.Status = STATUS_SUCCESS;
	irp->IoStatus.Information = 0;
	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

static void driver_unload(PDRIVER_OBJECT driver_object)
{
	events::cleanup();

	UNICODE_STRING symlink_name = RTL_CONSTANT_STRING(DARKEN_SYMLINK_NAME);
	IoDeleteSymbolicLink(&symlink_name);

	if (driver_object->DeviceObject)
	{
		IoDeleteDevice(driver_object->DeviceObject);
	}

	DBG_LOG("darken anticheat unloaded\n");
}

extern "C" NTSTATUS driver_entry(const PDRIVER_OBJECT driver_object, [[maybe_unused]] const PUNICODE_STRING registry_path)
{
	krnl::nt = get_ntoskrnl(driver_object);
	krnl::mm_pfn_database = reinterpret_cast<_MMPFN*>(get_mm_pfn_database());

	DBG_LOG("pfn db: %p\n", krnl::mm_pfn_database);

	/*if (emu::is_emulated())
	{
		return STATUS_ABANDONED;
	}*/

	UNICODE_STRING device_name = RTL_CONSTANT_STRING(DARKEN_DEVICE_NAME);
	UNICODE_STRING symlink_name = RTL_CONSTANT_STRING(DARKEN_SYMLINK_NAME);

	auto status = IoCreateDevice(
		driver_object,
		0,
		&device_name,
		FILE_DEVICE_UNKNOWN,
		FILE_DEVICE_SECURE_OPEN,
		FALSE,
		&g_device_object
	);

	if (!NT_SUCCESS(status))
	{
		DBG_LOG("failed to create device: 0x%x\n", status);
		return status;
	}

	g_device_object->Flags |= DO_BUFFERED_IO;
	g_device_object->Flags &= ~DO_DEVICE_INITIALIZING;

	status = IoCreateSymbolicLink(&symlink_name, &device_name);

	if (!NT_SUCCESS(status))
	{
		DBG_LOG("failed to create symbolic link: 0x%x\n", status);
		IoDeleteDevice(g_device_object);
		return status;
	}

	driver_object->MajorFunction[IRP_MJ_CREATE] = dispatch_create_close;
	driver_object->MajorFunction[IRP_MJ_CLOSE] = dispatch_create_close;
	driver_object->MajorFunction[IRP_MJ_DEVICE_CONTROL] = ioctl::dispatch;
	driver_object->DriverUnload = driver_unload;

	status = events::init();

	if (!NT_SUCCESS(status))
	{
		DBG_LOG("failed to initialize event system: 0x%x\n", status);
		IoDeleteSymbolicLink(&symlink_name);
		IoDeleteDevice(g_device_object);
		return status;
	}

	DBG_LOG("darken anticheat loaded\n");
	return STATUS_SUCCESS;
}
