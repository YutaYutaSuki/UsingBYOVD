#include "Utils.hpp"

#pragma comment(lib, "ntdll.lib")

NTSTATUS UtilsImpl::NtUnloadDriver(PUNICODE_STRING DriverServiceName) noexcept
{
	if (!m_initialized)
	{
		return STATUS_UNSUCCESSFUL;
	}

	return SC_NtUnloadDriver(DriverServiceName);
}

NTSTATUS
UtilsImpl::NtQuerySystemInformation(
	SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength) noexcept
{
	if (!m_initialized)
	{
		return STATUS_UNSUCCESSFUL;
	}

	return SC_NtQuerySystemInformation(
		SystemInformationClass,
		SystemInformation,
		SystemInformationLength,
		ReturnLength
	);
}

NTSTATUS UtilsImpl::RtlAdjustPrivilege(DWORD Privilege) noexcept
{
	if (!m_initialized)
	{
		return STATUS_UNSUCCESSFUL;
	}

	HANDLE hToken{ nullptr };
	NTSTATUS status{ STATUS_SUCCESS };

	status = SC_NtOpenProcessTokenEx(LongToHandle(-1),
		TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
		0,
		&hToken);
	if (!NT_SUCCESS(status))
	{
		return status;
	}

	TOKEN_PRIVILEGES tp = { 0 };
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid.LowPart = Privilege;
	tp.Privileges[0].Luid.HighPart = 0;
	tp.Privileges[0].Attributes = 2/*SE_PRIVILEGE_ENABLED*/;

	ULONG returnLength = 0;
	status = SC_NtAdjustPrivilegesToken(hToken,
		FALSE,
		&tp,
		sizeof(TOKEN_PRIVILEGES),
		nullptr,
		&returnLength);

	// Close Handle
	if (hToken)
	{
		this->NtClose(hToken);
	}

	return status;
}

NTSTATUS 
UtilsImpl::NtDeviceIoControlFile(
	HANDLE FileHandle, 
	ULONG IoControlCode, 
	PVOID InputBuffer, 
	ULONG InputBufferLength, 
	PVOID OutputBuffer,
	ULONG OutputBufferLength) noexcept
{
	if (!m_initialized)
	{
		return STATUS_UNSUCCESSFUL;
	}

	IO_STATUS_BLOCK IoStatusBlock{};
	return SC_NtDeviceIoControlFile(
		FileHandle,
		nullptr,
		nullptr,
		nullptr,
		&IoStatusBlock,
		IoControlCode,
		InputBuffer,
		InputBufferLength,
		OutputBuffer,
		OutputBufferLength
	);
}

NTSTATUS 
UtilsImpl::NtClose(HANDLE Handle) noexcept
{
	if (!m_initialized)
	{
		return STATUS_UNSUCCESSFUL;
	}
	return SC_NtClose(Handle);
}

NTSTATUS 
UtilsImpl::NtCreateFile(
	PHANDLE FileHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PIO_STATUS_BLOCK IoStatusBlock,
	PLARGE_INTEGER AllocationSize,
	ULONG FileAttributes,
	ULONG ShareAccess,
	ULONG CreateDisposition,
	ULONG CreateOptions, 
	PVOID EaBuffer,
	ULONG EaLength) noexcept
{
	if (!m_initialized)
	{
		return STATUS_UNSUCCESSFUL;
	}

	return SC_NtCreateFile(
		FileHandle,
		DesiredAccess,
		ObjectAttributes,
		IoStatusBlock,
		AllocationSize,
		FileAttributes,
		ShareAccess,
		CreateDisposition,
		CreateOptions,
		EaBuffer,
		EaLength
	);
}

BOOLEAN Utils::InitSyscalls() noexcept
{
	return g_Utils->InitializeSyscalls();
}

NTSTATUS Utils::NtLoadDriver(PUNICODE_STRING DriverServiceName) noexcept
{
	return g_Utils->NtLoadDriver(DriverServiceName);
}

NTSTATUS Utils::NtUnloadDriver(PUNICODE_STRING DriverServiceName) noexcept
{
	return g_Utils->NtUnloadDriver(DriverServiceName);
}

NTSTATUS Utils::NtQuerySystemInformation(
	SYSTEM_INFORMATION_CLASS SystemInformationClass, 
	PVOID SystemInformation, 
	ULONG SystemInformationLength, 
	PULONG ReturnLength) noexcept
{
	return g_Utils->NtQuerySystemInformation(SystemInformationClass,
		SystemInformation,
		SystemInformationLength,
		ReturnLength
	);
}

NTSTATUS Utils::RtlAdjustPrivilege(DWORD Privilege) noexcept
{
	return g_Utils->RtlAdjustPrivilege(Privilege);
}

NTSTATUS 
Utils::NtDeviceIoControlFile(
	HANDLE FileHandle,
	ULONG IoControlCode, 
	PVOID InputBuffer, 
	ULONG InputBufferLength, 
	PVOID OutputBuffer, 
	ULONG OutputBufferLength) noexcept
{
	return g_Utils->NtDeviceIoControlFile(FileHandle,
		IoControlCode,
		InputBuffer,
		InputBufferLength,
		OutputBuffer,
		OutputBufferLength);
}

NTSTATUS Utils::NtClose(HANDLE Handle) noexcept
{
	
	return g_Utils->NtClose(Handle);
	
}

NTSTATUS Utils::NtCreateFile(
	PHANDLE FileHandle, 
	ACCESS_MASK DesiredAccess, 
	POBJECT_ATTRIBUTES ObjectAttributes, 
	PIO_STATUS_BLOCK IoStatusBlock, 
	PLARGE_INTEGER AllocationSize, 
	ULONG FileAttributes, 
	ULONG ShareAccess, 
	ULONG CreateDisposition,
	ULONG CreateOptions, 
	PVOID EaBuffer,
	ULONG EaLength) noexcept
{
	return g_Utils->NtCreateFile(FileHandle,
		DesiredAccess,
		ObjectAttributes,
		IoStatusBlock,
		AllocationSize,
		FileAttributes,
		ShareAccess,
		CreateDisposition,
		CreateOptions,
		EaBuffer,
		EaLength);
}

