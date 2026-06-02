#pragma once
#include <windows.h>
#include <string>


namespace DriverLoader
{
	enum class AllocationMode
	{
		AllocatePool,
		AllocateIndependentPages
	};


	//0x1 bytes (sizeof)
	typedef struct _PS_PROTECTION
	{
		union
		{
			UCHAR Level;                                                        //0x0
			struct
			{
				UCHAR Type : 3;                                                   //0x0
				UCHAR Audit : 1;                                                  //0x0
				UCHAR Signer : 4;                                                 //0x0
			};
		};
	}PS_PROTECTION, *PPS_PROTECTION;

	typedef enum _PS_PROTECTED_SIGNER
	{
		PsProtectedSignerNone			= 0,
		PsProtectedSignerAuthenticode	= 1,
		PsProtectedSignerCodeGen		= 2,
		PsProtectedSignerAntimalware	= 3,
		PsProtectedSignerLsa			= 4,
		PsProtectedSignerWindows		= 5,
		PsProtectedSignerWinTcb			= 6,
		PsProtectedSignerWinSystem		= 7,
		PsProtectedSignerApp			= 8,
		PsProtectedSignerMax
	} PS_PROTECTED_SIGNER;

	typedef enum _PS_PROTECTED_TYPE
	{
		PsProtectedTypeNone				= 0,
		PsProtectedTypeProtectedLight	= 1,
		PsProtectedTypeProtected		= 2,
		PsProtectedTypeMax				= 3
	} PS_PROTECTED_TYPE;


	auto GetKernelBase() -> ULONG64;


	BOOLEAN
	PrivilegeEscalation(
		ULONG64 SourceProcess,
		ULONG64 TargetProcess,
		ULONG	OffsetOfProcessToken);

	BOOLEAN
	SetProcessProtection(
		ULONG64			Process,
		ULONG			OffsetOfProtection,
		PS_PROTECTION*	Protection);

	BOOLEAN
	SetSignatureLevel(
		ULONG64			Process,
		ULONG			OffsetOfSignatureLevel,
		PUCHAR			SignatureLevel);


	auto InitMemoryManager()->BOOLEAN;

	BOOLEAN
	MapperDriver(
		const PUCHAR DriverData,
		AllocationMode Mode = AllocationMode::AllocatePool);

	BOOLEAN
	MapperDriver(
		const std::string_view DriverPath,
		AllocationMode Mode = AllocationMode::AllocatePool);
}

