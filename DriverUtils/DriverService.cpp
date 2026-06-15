#include <windows.h>
#include <winternl.h>
#include "DriverService.hpp"
#include "Log.hpp"
#include <string>
#include <format>
#include <memory>
#include <filesystem>

#pragma comment(lib, "ntdll.lib")

namespace fs = std::filesystem;

NTSTATUS DriverService::EnablePrivilege()
{
	return Utils::RtlAdjustPrivilege(SE_LOAD_DRIVER_PRIVILEGE);
}

NTSTATUS DriverService::LoadDriver(PUNICODE_STRING DriverServiceName)
{
	return Utils::NtLoadDriver(DriverServiceName);
}

NTSTATUS DriverService::UnloadDriver(PUNICODE_STRING DriverServiceName)
{
	return Utils::NtUnloadDriver(DriverServiceName);
}

NTSTATUS DriverService::RegisterService()
{
	if (m_bIsRegisted)
	{
		LOG("[-] Service already registered" << std::endl);
		return STATUS_OBJECT_NAME_COLLISION;
	}

	if (m_serviceName.empty() ||
		m_driverPath.empty())
	{
		LOG("[-] Service name or driver path is empty" << std::endl);
		return STATUS_INVALID_PARAMETER;
	}

	const std::wstring serviceName	= std::wstring(m_serviceName.begin(), m_serviceName.end());

	// Build registry paths using filesystem for clean and safe concatenation
	const fs::path wstrServicesPath = fs::path(L"SYSTEM") / L"CurrentControlSet" / L"Services" / serviceName;
	const fs::path wstrDriverPath	= fs::path(L"\\Registry\\Machine\\System") / L"CurrentControlSet" / L"Services" / serviceName;

	// ====================== RAII Registry Key Guard ======================
	struct RegKeyDeleter
	{
		using pointer = HKEY;
		void operator()(HKEY hKey) const noexcept
		{
			if (hKey)
			{
				RegCloseKey(hKey);
			}
		}
	};

	std::unique_ptr<HKEY, RegKeyDeleter> hDriverService;

	HKEY hRaw{ nullptr };
	LSTATUS result = RegCreateKeyW(HKEY_LOCAL_MACHINE, wstrServicesPath.c_str(), &hRaw);
	if (result != ERROR_SUCCESS)
	{
		LOG(std::format("[-] Failed to create service key (0x{:X})", result) << std::endl);
		return STATUS_REGISTRY_IO_FAILED;
	}
	hDriverService.reset(hRaw);

	const DWORD ServiceTypeKernel	= 1;  // SERVICE_KERNEL_DRIVER
	const DWORD ServiceErrorControl = 1;  // SERVICE_ERROR_NORMAL
	const DWORD ServiceStartDemand	= 3;  // SERVICE_DEMAND_START

	// Build ImagePath with \??\ prefix
	const fs::path driverPath		= m_driverPath;
	const std::wstring imagePath	= LR"(\??\)" + driverPath.wstring();

	// ImagePath
	result = RegSetKeyValueW(hDriverService.get(),
							 nullptr,
							 L"ImagePath",
							 REG_EXPAND_SZ,
							 imagePath.c_str(),
							 static_cast<DWORD>((imagePath.size() + 1) * sizeof(wchar_t)));

	if (result != ERROR_SUCCESS)
	{
		LOG(std::format("[-] Failed to set ImagePath (0x{:X})", result) << std::endl);
		RegDeleteTreeW(HKEY_LOCAL_MACHINE, wstrServicesPath.c_str());
		return STATUS_REGISTRY_IO_FAILED;
	}

	// Required registry values
	RegSetKeyValueW(hDriverService.get(), nullptr, L"Type", REG_DWORD, &ServiceTypeKernel, sizeof(DWORD));
	RegSetKeyValueW(hDriverService.get(), nullptr, L"ErrorControl", REG_DWORD, &ServiceErrorControl, sizeof(DWORD));
	RegSetKeyValueW(hDriverService.get(), nullptr, L"Start", REG_DWORD, &ServiceStartDemand, sizeof(DWORD));

	m_wRegDriverPath	= wstrDriverPath.wstring();
	m_wRegServicePath	= wstrServicesPath.wstring();
	m_bIsRegisted		= TRUE;
	return STATUS_SUCCESS;
}

NTSTATUS DriverService::LoadDriver()
{
	// check if service is registered
	if (!m_bIsRegisted)
	{
		LOG("[-] Service not registered, cannot load driver" << std::endl);
		return STATUS_INVALID_PARAMETER;
	}

	if (m_wRegDriverPath.empty())
	{
		LOG("[-] Driver path is empty, cannot load driver" << std::endl);
		return STATUS_INVALID_PARAMETER;
	}

	if (m_wRegServicePath.empty())
	{
		LOG("[-] Service path is empty, cannot load driver" << std::endl);
		return STATUS_INVALID_PARAMETER;
	}

	NTSTATUS ntStatus = EnablePrivilege();
	if (!NT_SUCCESS(ntStatus))
	{
		RegDeleteTreeW(HKEY_LOCAL_MACHINE, m_wRegServicePath.c_str());
		LOG(std::format("[-] Failed to acquire SeLoadDriverPrivilege (0x{:X})", ntStatus) << std::endl);
		return ntStatus;
	}

	// Load the driver
	UNICODE_STRING ustrDriver{};
	RtlInitUnicodeString(&ustrDriver, m_wRegDriverPath.c_str());
	ntStatus = LoadDriver(&ustrDriver);
	if (ntStatus == STATUS_OBJECT_NAME_EXISTS)
	{
		LOGW("[-] Driver already loaded, attempting to unload first...\n");
		ntStatus = UnloadDriver(&ustrDriver);
		if (!NT_SUCCESS(ntStatus))
		{
			LOGW(std::format(L"[-] NtUnloadDriver failed: 0x{:X}\n", ntStatus));
		}

		ntStatus = LoadDriver(&ustrDriver);
		LOGW(std::format(L"[+] NtLoadDriver after unload: 0x{:X}\n", ntStatus));
	}

	if (!NT_SUCCESS(ntStatus) && ntStatus != STATUS_OBJECT_NAME_COLLISION)
	{
		LOGW("[-] Load failed, cleaning registry...\n");
		RegDeleteTreeW(HKEY_LOCAL_MACHINE, m_wRegServicePath.c_str());

		m_bIsRegisted = FALSE;
		return ntStatus;
	}

	if (ntStatus == STATUS_OBJECT_NAME_COLLISION)
	{
		return STATUS_SUCCESS;
	}

	return ntStatus;
}

NTSTATUS DriverService::StopAndUnregister()
{
	if (!m_bIsRegisted)
	{
		LOG("[-] Service not registered, cannot load driver" << std::endl);
		return STATUS_INVALID_PARAMETER;
	}

	if (m_wRegDriverPath.empty())
	{
		LOG("[-] Driver path is empty, cannot unregister" << std::endl);
		return STATUS_INVALID_PARAMETER;
	}

	if (m_wRegServicePath.empty())
	{
		LOG("[-] Service path is empty, cannot unregister" << std::endl);
		return STATUS_INVALID_PARAMETER;
	}

	// ====================== Unload Driver ======================
	NTSTATUS ntStatus = EnablePrivilege();
	if (!NT_SUCCESS(ntStatus))
	{
		LOG(std::format("[-] Failed to acquire SeLoadDriverPrivilege (0x{:X}). Run as Administrator!", ntStatus)
			<< std::endl);
		return ntStatus;
	}

	UNICODE_STRING ustrDriver{};
	RtlInitUnicodeString(&ustrDriver, m_wRegDriverPath.c_str());
	ntStatus = UnloadDriver(&ustrDriver);
	if (!NT_SUCCESS(ntStatus))
	{
		LOG("[-] Driver Unload Failed!!" << std::endl);
	}

	ntStatus = RegDeleteTreeW(HKEY_LOCAL_MACHINE, m_wRegServicePath.c_str());
	if (ntStatus != ERROR_SUCCESS)
	{
		return STATUS_REGISTRY_IO_FAILED;
	}

	m_bIsRegisted = FALSE;
	m_wRegServicePath.clear();
	return ntStatus;
}