#pragma once
#include <Windows.h>
#include <winternl.h>
#include "Singleton.hpp"
#include "ObjectProxy.hpp"
#include "SCSyscalls.h"

#ifndef STATUS_BUFFER_TOO_SMALL
#define STATUS_BUFFER_TOO_SMALL ((NTSTATUS)0xC0000023L)
#endif

#ifndef STATUS_INFO_LENGTH_MISMATCH
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
#endif // !STATUS_INFO_LENGTH_MISMATCH

#ifndef STATUS_REGISTRY_IO_FAILED
#define STATUS_REGISTRY_IO_FAILED ((NTSTATUS)0xC0000257L)
#endif

#ifndef STATUS_UNSUCCESSFUL
#define STATUS_UNSUCCESSFUL ((NTSTATUS)0xC0000001L)
#endif

#ifndef STATUS_OBJECT_NAME_EXISTS
#define STATUS_OBJECT_NAME_EXISTS ((NTSTATUS)0x40000000L)
#endif

#ifndef STATUS_OBJECT_NAME_COLLISION
#define STATUS_OBJECT_NAME_COLLISION ((NTSTATUS)0xC0000035L)
#endif


#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif



class UtilsImpl final : public Singleton<UtilsImpl>
{
	friend class Singleton<UtilsImpl>;

public:
	explicit UtilsImpl(Token) noexcept : UtilsImpl()
	{
	}

	// ====================== Syscall ======================
	BOOLEAN InitializeSyscalls() noexcept
	{
#ifdef EGG_MODE
		if (!SC_Initialize() || !SC_HatchEggs())
		{
			return false;
		}
#endif

		m_initialized = TRUE;
		return TRUE;
	}

	NTSTATUS NtLoadDriver(PUNICODE_STRING DriverServiceName) noexcept
	{
		return SC_NtLoadDriver(DriverServiceName);
	}

	NTSTATUS NtUnloadDriver(PUNICODE_STRING DriverServiceName) noexcept;

	NTSTATUS NtQuerySystemInformation(
		SYSTEM_INFORMATION_CLASS SystemInformationClass,
		PVOID                    SystemInformation,
		ULONG                    SystemInformationLength,
		PULONG                   ReturnLength) noexcept;

	NTSTATUS RtlAdjustPrivilege(
		DWORD Privilege) noexcept;

	NTSTATUS NtDeviceIoControlFile(
		HANDLE           FileHandle,
		ULONG            IoControlCode,
		PVOID            InputBuffer,
		ULONG            InputBufferLength,
		PVOID            OutputBuffer,
		ULONG            OutputBufferLength) noexcept;

	NTSTATUS NtClose(HANDLE Handle) noexcept;

	NTSTATUS NtCreateFile(
		PHANDLE            FileHandle,
		ACCESS_MASK        DesiredAccess,
		POBJECT_ATTRIBUTES ObjectAttributes,
		PIO_STATUS_BLOCK   IoStatusBlock,
		PLARGE_INTEGER     AllocationSize,
		ULONG              FileAttributes,
		ULONG              ShareAccess,
		ULONG              CreateDisposition,
		ULONG              CreateOptions,
		PVOID              EaBuffer,
		ULONG              EaLength) noexcept;

private:
	UtilsImpl() noexcept = default;
	bool m_initialized{ false };
};

inline ObjectProxy<UtilsImpl> g_Utils{};

namespace Utils
{
	BOOLEAN InitSyscalls() noexcept;


	NTSTATUS NtLoadDriver(PUNICODE_STRING DriverServiceName) noexcept;
	

	NTSTATUS NtUnloadDriver(PUNICODE_STRING DriverServiceName) noexcept;
	

	NTSTATUS NtQuerySystemInformation(
		SYSTEM_INFORMATION_CLASS SystemInformationClass,
		PVOID                    SystemInformation,
		ULONG                    SystemInformationLength,
		PULONG                   ReturnLength) noexcept;
	
	NTSTATUS RtlAdjustPrivilege(DWORD Privilege) noexcept;


	NTSTATUS NtDeviceIoControlFile(
		HANDLE           FileHandle,
		ULONG            IoControlCode,
		PVOID            InputBuffer,
		ULONG            InputBufferLength,
		PVOID            OutputBuffer,
		ULONG            OutputBufferLength) noexcept;

	NTSTATUS NtClose(HANDLE Handle) noexcept;
	


	 NTSTATUS NtCreateFile(
		 PHANDLE            FileHandle,
		 ACCESS_MASK        DesiredAccess,
		 POBJECT_ATTRIBUTES ObjectAttributes,
		 PIO_STATUS_BLOCK   IoStatusBlock,
		 PLARGE_INTEGER     AllocationSize,
		 ULONG              FileAttributes,
		 ULONG              ShareAccess,
		 ULONG              CreateDisposition,
		 ULONG              CreateOptions,
		 PVOID              EaBuffer,
		 ULONG              EaLength) noexcept;
	
}
