#include "ProcessCtr.h"
#include "FileUtils.hpp"
#include "ProcessCtrBin.hpp"
#include "Log.hpp"

BOOLEAN
ProcessCtr::Initialize() noexcept
{
	if (m_bInitialized)
	{
		return TRUE;
	}

	// Create the driver file from the resource data
	std::string driverFullPath;
	if (!FileUtils::CreateDriverFile(driverFullPath,
		(const char*)ProcessCtrBin::hexData,
		ProcessCtrBin::hexSize,
		ProcessCtrBin::Key))
	{
		LOG("[-] CreateDriverFile failed");
		return FALSE;
	}

	// Register and start the driver service
	// std::string strServiceName{ HwRwSys::service };

	// Get the device name from the resource data
	std::string serviceName = "ProcessCtr";
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

VOID ProcessCtr::Uninitialize()
{
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

BOOLEAN ProcessCtr::KillProcess(ULONG Pid)
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

HANDLE ProcessCtr::CreateDevice()
{
	auto hDevice = CreateFileA("\\\\.\\ProcessCtr",
							   GENERIC_READ | GENERIC_WRITE,
							   0,
							   nullptr,
							   OPEN_EXISTING,
							   FILE_ATTRIBUTE_NORMAL,
							   nullptr);

	return hDevice;
}
