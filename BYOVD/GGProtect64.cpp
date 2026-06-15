#include "GGProtect64.h"
#include "FileUtils.hpp"
#include "GGProtect64Bin.hpp"
#include "Log.hpp"

BOOLEAN
GGProtect64::Initialize() noexcept
{
	if (m_bInitialized)
	{
		return TRUE;
	}

	// Create the driver file from the resource data
	std::string driverFullPath;
	if (!FileUtils::CreateDriverFile(driverFullPath,
									 (const char*)GGProtect64Bin::hexData,
									 GGProtect64Bin::hexSize,
									 GGProtect64Bin::Key))
	{
		LOG("[-] CreateDriverFile failed");
		return FALSE;
	}

	// Register and start the driver service
	// std::string strServiceName{ HwRwSys::service };

	// Get the device name from the resource data
	std::string serviceName = "GGProtect64";
	if (serviceName.empty())
	{
		return FALSE;
	}

	m_pDriverService = new DriverService(driverFullPath, serviceName);
	if (!m_pDriverService)
	{
		LOG("[-] Failed to create DriverService instance");
		return FALSE;
	}

	if (!NT_SUCCESS(m_pDriverService->RegisterService()))
	{
		LOG("[-] Failed to register driver service");
		return FALSE;
	}

	// Load the driver
	if (!NT_SUCCESS(m_pDriverService->LoadDriver()))
	{
		LOG("[-] Failed to load driver");
		return FALSE;
	}

	// Create Device 
	m_hDevice = CreateDevice();
	if (INVALID_HANDLE_VALUE == m_hDevice)
	{
		return FALSE;
	}

	m_bInitialized = TRUE;
	return TRUE;
}

VOID GGProtect64::Uninitialize()
{
	/*if (INVALID_HANDLE_VALUE != m_hDevice)
	{
		DWORD dwPid = GetCurrentProcessId() ^ CHECK_VALUE;
		DWORD dwResult{};


		DeviceIoControl(m_hDevice,
						IOCTL_DRIVER_UNLOAD,
						&dwPid,
						sizeof(dwPid),
						nullptr,
						0,
						&dwResult,
						nullptr);
	}*/



	if (m_pDriverService)
	{
		m_pDriverService->StopAndUnregister();

		delete m_pDriverService;
		m_pDriverService = nullptr;
	}

	if (INVALID_HANDLE_VALUE != m_hDevice)
	{
		CloseHandle(m_hDevice);
		m_hDevice = INVALID_HANDLE_VALUE;
	}

	m_bInitialized = FALSE;
}

BOOLEAN GGProtect64::KillProcess(ULONG Pid)
{
	DWORD dwRead{ 0 };

	return DeviceIoControl(m_hDevice,
		IOCTL_KILL_PROCESS,
		&Pid,
		sizeof(Pid),
		nullptr,
		0,
		&dwRead,
		nullptr);

}

HANDLE GGProtect64::CreateDevice()
{
	auto hDevice = CreateFileA("\\\\.\\GGProtect64",
							   GENERIC_READ | GENERIC_WRITE,
							   0,
							   nullptr,
							   OPEN_EXISTING,
							   FILE_ATTRIBUTE_NORMAL,
							   nullptr);

	DWORD dwRequest = GetCurrentProcessId() ^ CHECK_VALUE;
	DWORD dwResult = 0;
	if (DeviceIoControl(hDevice,
						IOCTL_DRIVER_LOAD,
						&dwRequest,
						sizeof(dwRequest),
						NULL,
						0,
						&dwResult,
						NULL))
	{
		return hDevice;
	}
	else
	{
		CloseHandle(hDevice);
		hDevice = INVALID_HANDLE_VALUE;
	}

	return hDevice;
}
