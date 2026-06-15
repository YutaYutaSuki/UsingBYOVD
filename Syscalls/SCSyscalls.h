#pragma once
#include <windows.h>
#include <winternl.h>

#ifndef _PS_ATTRIBUTE_LIST
typedef struct _PS_ATTRIBUTE
{
	ULONG_PTR Attribute;
	SIZE_T    Size;
	union
	{
		ULONG_PTR Value;
		PVOID     ValuePtr;
	};
	PSIZE_T   ReturnLength;
} PS_ATTRIBUTE, * PPS_ATTRIBUTE;

typedef struct _PS_ATTRIBUTE_LIST
{
	SIZE_T       TotalLength;
	PS_ATTRIBUTE Attributes[1];
} PS_ATTRIBUTE_LIST, * PPS_ATTRIBUTE_LIST;
#endif

typedef struct _SC_SSN_ENTRY
{
	DWORD  Count;
	struct
	{
		DWORD Build;
		DWORD Ssn;
	} Entries[64];
} SC_SSN_ENTRY;

/* Export entry used during FreshyCalls / Hell's Gate scanning */
typedef struct _SC_EXPORT
{
	PVOID Address;
	DWORD Hash;
	DWORD Ordinal;
} SC_EXPORT, * PSC_EXPORT;

#define EGG_MODE 1

#ifdef __cplusplus
extern "C" {
#endif
	/* =========================================================================
	 *  Runtime initialization
	 *  Halo's Gate  -- Hell's Gate + neighbor scan for hooks
	 * ========================================================================= */

#ifdef EGG_MODE

	EXTERN_C BOOL SC_Initialize(VOID);

	EXTERN_C BOOL SC_HatchEggs(VOID);  /* Patch egg markers -> syscall opcode */



	EXTERN_C BOOLEAN RunSyscallInit();

	/* =========================================================================
	 *  Syscall function prototypes
	 * ========================================================================= */

	EXTERN_C
		NTSTATUS
		NTAPI
		SC_NtLoadDriver(PUNICODE_STRING DriverServiceName);

	EXTERN_C
		NTSTATUS
		NTAPI
		SC_NtUnloadDriver(PUNICODE_STRING DriverServiceName);


	EXTERN_C
		NTSTATUS
		NTAPI
		SC_NtQuerySystemInformation(
			SYSTEM_INFORMATION_CLASS,
			PVOID,
			ULONG,
			PULONG);

	EXTERN_C
		NTSTATUS
		NTAPI
		SC_NtDeviceIoControlFile(
			HANDLE           FileHandle,
			HANDLE           Event,
			PIO_APC_ROUTINE  ApcRoutine,
			PVOID            ApcContext,
			PIO_STATUS_BLOCK IoStatusBlock,
			ULONG            IoControlCode,
			PVOID            InputBuffer,
			ULONG            InputBufferLength,
			PVOID            OutputBuffer,
			ULONG            OutputBufferLength
		);

	EXTERN_C
		NTSTATUS
		NTAPI
		SC_NtOpenProcessTokenEx(
			HANDLE      ProcessHandle,
			ACCESS_MASK DesiredAccess,
			ULONG       HandleAttributes,
			PHANDLE     TokenHandle
		);

	EXTERN_C
		NTSTATUS
		NTAPI
		SC_NtAdjustPrivilegesToken(
			HANDLE TokenHandle,
			BOOLEAN DisableAllPrivileges,
			PTOKEN_PRIVILEGES NewState,
			ULONG BufferLength,
			PTOKEN_PRIVILEGES PreviousState,
			PULONG ReturnLength
		);

	EXTERN_C
		NTSTATUS
		NTAPI
		SC_NtClose(HANDLE Handle);


	EXTERN_C
		NTSTATUS
		NTAPI
		SC_NtCreateFile(
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
			ULONG              EaLength
		);

#endif


#ifdef __cplusplus
}
#endif