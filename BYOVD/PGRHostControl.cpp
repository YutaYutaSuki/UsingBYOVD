#include "PGRHostControl.h"
#include "PGRHostControlBin.hpp"
#include "FileUtils.hpp"
#include "va2pa.h"
#include "Log.hpp"


BOOLEAN PGRHostControl::Initialize() noexcept
{
	if (m_bInitialized)
	{
		return m_bInitialized;
	}

	// Create the driver file from the resource data
	std::string driverFullPath;
	if (!FileUtils::CreateDriverFile(driverFullPath,
								     (const char*)PGRHostControlBin::hexData,
								     PGRHostControlBin::hexSize,
								     PGRHostControlBin::Key))
	{
		LOG("[-] CreateDriverFile failed");
		return FALSE;
	}

	std::string serviceName = "PGRHostControl";
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
	std::string deviceName = "\\\\.\\PGRHostControl";
	m_hDevice = CreateDevice(deviceName.c_str());

	if (INVALID_HANDLE_VALUE == m_hDevice)
	{
		return FALSE;
	}

	m_bInitialized = TRUE;
	return TRUE;
}

VOID PGRHostControl::Uninitialize()
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

BOOLEAN
PGRHostControl::KernelRead(
	PVOID	VirtualAddress,
	PVOID	ReadBuffer,
	SIZE_T	ReadSize)
{
	if (INVALID_HANDLE_VALUE == m_hDevice)
	{
		LOG("[-] PGRHostControl device handle is invalid. Ensure the driver is loaded and the device is accessible.");
		return FALSE;
	}

	if (!VirtualAddress || !ReadBuffer || !ReadSize || !m_bInitialized)
	{
		LOG("[-] Invalid parameters for KernelRead.");
		return FALSE;
	}

	if (ReadSize <= 0x1000)
	{
		PVOID pPhysicalAddress = this->VirtualToPhysical(VirtualAddress);
		if (!pPhysicalAddress)
		{
			LOG("VirtualToPhysical failed!!!");
			return FALSE;
		}

		MapRequest request{};
		request.PhysicalAddress = pPhysicalAddress;
		request.Size = ReadSize;

		auto pMappedAddress = MapPhysicalMemory(&request);
		if (!pMappedAddress)
		{
			LOG("[-] Failed to map physical memory. Error code:" << std::hex << GetLastError() << std::dec);
			return FALSE;
		}

		RtlCopyMemory(ReadBuffer, pMappedAddress, ReadSize);
		UnmapPhysicalMemory(&request);
	}
	else
	{
		// ReadSize > 0x1000, need to read page by page
		ULONG NumberOfPages = static_cast<ULONG>((ReadSize + 0xFFF) / 0x1000);
		for (auto i{ 0u }; i < NumberOfPages; ++i)
		{
			PVOID pPhysicalAddress = VirtualToPhysical(reinterpret_cast<PUCHAR>(VirtualAddress) + i * 0x1000);
			if (!pPhysicalAddress)
			{
				LOG("VirtualToPhysical failed!!!");
				return FALSE;
			}

			if (i != NumberOfPages - 1)
			{
				MapRequest request{};
				request.PhysicalAddress = pPhysicalAddress;
				request.Size = 0x1000;

				auto pMappedAddress = MapPhysicalMemory(&request);
				if (!pMappedAddress)
				{
					LOG("[-] Failed to map physical memory. Error code: %lu" << std::hex << GetLastError() << std::dec);
					return FALSE;
				}

				RtlCopyMemory(reinterpret_cast<PUCHAR>(ReadBuffer) + i * 0x1000, pMappedAddress, 0x1000);
				UnmapPhysicalMemory(&request);
			}
			else
			{
				// Last page, calculate the remaining size
				ULONG RemainingSize = static_cast<ULONG>(ReadSize - i * 0x1000);

				MapRequest request{};
				request.PhysicalAddress = pPhysicalAddress;
				request.Size = RemainingSize;

				auto pMappedAddress = MapPhysicalMemory(&request);
				if (!pMappedAddress)
				{
					LOG("[-] Failed to map physical memory. Error code: %lu" << std::hex << GetLastError() << std::dec);
					return FALSE;
				}

				RtlCopyMemory(reinterpret_cast<PUCHAR>(ReadBuffer) + i * 0x1000, pMappedAddress, RemainingSize);
				UnmapPhysicalMemory(&request);
			}
		}


	}

	return TRUE;
}

BOOLEAN
PGRHostControl::KernelWrite(
	PVOID VirtualAddress,
	PVOID WriteBuffer,
	SIZE_T WriteSize)
{
	if (!VirtualAddress || !WriteBuffer || !WriteSize || !m_bInitialized)
	{
		LOG("[-] Invalid parameters for KernelWrite.");
		return FALSE;
	}

	if (WriteSize <= 0x1000)
	{
		PVOID pPhysicalAddress = this->VirtualToPhysical(VirtualAddress);
		if (!pPhysicalAddress)
		{

			LOG("[-] Failed to translate virtual address to physical address using MemoryMap.");
			return FALSE;

		}
		
		MapRequest request{};
		request.PhysicalAddress = pPhysicalAddress;
		request.Size = WriteSize;

		auto pMappedAddress = MapPhysicalMemory(&request);
		if (!pMappedAddress)
		{
			LOG("[-] Failed to map physical memory.");
			return FALSE;
		}

		RtlCopyMemory(pMappedAddress, WriteBuffer, WriteSize);
		UnmapPhysicalMemory(&request);
	}
	else
	{
		// WriteSize > 0x1000
		ULONG NumberOfPages = static_cast<ULONG>((WriteSize + 0xFFF) / 0x1000);
		for (auto i{ 0u }; i < NumberOfPages; ++i)
		{
			PVOID pPhysicalAddress = VirtualToPhysical(reinterpret_cast<PUCHAR>(VirtualAddress) + i * 0x1000);
			if (!pPhysicalAddress)
			{

				LOG("[-] Failed to translate virtual address to physical address using MemoryMap.");
				return FALSE;

			}
			if (i != NumberOfPages - 1)
			{
				MapRequest request{};
				request.PhysicalAddress = pPhysicalAddress;
				request.Size = 0x1000;

				auto pMappedAddress = MapPhysicalMemory(&request);
				if (!pMappedAddress)
				{
					LOG("[-] Failed to map physical memory.");
					return FALSE;
				}

				RtlCopyMemory(pMappedAddress, reinterpret_cast<PUCHAR>(WriteBuffer) + i * 0x1000, 0x1000);
				UnmapPhysicalMemory(&request);
			}
			else
			{
				// Last page, calculate the remaining size
				ULONG RemainingSize = static_cast<ULONG>(WriteSize - i * 0x1000);

				MapRequest request{};
				request.PhysicalAddress = pPhysicalAddress;
				request.Size = RemainingSize;

				auto pMappedAddress = MapPhysicalMemory(&request);
				if (!pMappedAddress)
				{
					LOG("[-] Failed to map physical memory.");
					return FALSE;
				}

				RtlCopyMemory(pMappedAddress, reinterpret_cast<PUCHAR>(WriteBuffer) + i * 0x1000, RemainingSize);
				UnmapPhysicalMemory(&request);
			}
		}
	}

	return TRUE;
}


PVOID
PGRHostControl::MapPhysicalMemory(
	PMapRequest Request)
{
	DWORD dwBytesReturned = 0;

	if (DeviceIoControl(m_hDevice,
						IOCTL_MAP,
						Request,
						sizeof(MapRequest),
						Request,
						sizeof(MapRequest),
						&dwBytesReturned,
						nullptr))
	{
		return Request->MappingAddress;
	}
	return nullptr;
}

VOID
PGRHostControl::UnmapPhysicalMemory(
	PMapRequest Request)
{
	if (!Request)
	{
		return;
	}

	DWORD dwBytesReturned = 0;

	DeviceIoControl(m_hDevice,
					IOCTL_UNMAP,
					Request,
					sizeof(MapRequest),
					nullptr,
					0,
					&dwBytesReturned,
					nullptr);
}

PVOID
PGRHostControl::VirtualToPhysical(PVOID VirtualAddress)
{
	return Va2Pa(VirtualAddress);
}

HANDLE PGRHostControl::CreateDevice(const char* DeviceName)
{
	m_hDevice = CreateFileA(DeviceName,
		GENERIC_READ | GENERIC_WRITE,
		0,
		nullptr,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		nullptr);

	return m_hDevice;
}


