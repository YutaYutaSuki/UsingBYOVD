#include "BiosToolCommonDriver.h"
#include "FileUtils.hpp"
#include "BiosToolCommonDriverBin.hpp"
#include "Log.hpp"
#include "va2pa.h"


BOOLEAN BiosToolCommonDriver::Initialize() noexcept
{
	if (m_bInitialized)
	{
		return TRUE;
	}

	// Create the driver file from the resource data
	std::string driverFullPath;
	if (!FileUtils::CreateDriverFile(driverFullPath,
									 (const char*)BiosToolCommonDriverBin::hexData,
									 BiosToolCommonDriverBin::hexDataSize,
									 BiosToolCommonDriverBin::Key))
	{
		LOG("[-] CreateDriverFile failed");
		return FALSE;
	}

	// Register and start the driver service
	// std::string strServiceName{ HwRwSys::service };

	// Get the device name from the resource data
	std::string serviceName = FileUtils::GetServiceName(BiosToolCommonDriverBin::service,
														BiosToolCommonDriverBin::serviceLength,
														BiosToolCommonDriverBin::Key);
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
	std::string_view strDeviceName = "\\\\.\\BiosToolCommonDriver";
	m_hDevice = CreateDevice(strDeviceName.data());
	if (INVALID_HANDLE_VALUE == m_hDevice)
	{
		return FALSE;
	}

	m_bInitialized = TRUE;
	return TRUE;
}

VOID BiosToolCommonDriver::Uninitialize()
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
BiosToolCommonDriver::KernelRead(
	PVOID VirtualAddress,
	PVOID ReadBuffer,
	SIZE_T ReadSize)
{
	if (!VirtualAddress || !ReadBuffer || !ReadSize || !m_bInitialized)
	{
		return FALSE;
	}

	BOOLEAN bRet = FALSE;

	if (ReadSize < 0x1000)
	{
		PVOID pPhysicalAddress = VirtualToPhysical(VirtualAddress);
		if (!pPhysicalAddress)
		{

			LOG("[-] Failed to translate virtual address to physical address using MemoryMap.");
			return FALSE;

		}

		bRet = ReadPhysicalMemory(reinterpret_cast<PVOID>(pPhysicalAddress),
								  static_cast<ULONG>(ReadSize),
								  ReadBuffer);
		if (!bRet)
		{
			//std::cout << "[-] ReadPhysicalMemory failed for physical address:" << pPhysicalAddress << "" << std::endl;
			LOG("[-] ReadPhysicalMemory failed for physical address: " << pPhysicalAddress);
		}
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

				LOG("[-] Failed to translate virtual address to physical address using MemoryMap.");
				return FALSE;

			}
			if (i != NumberOfPages - 1)
			{
				bRet = ReadPhysicalMemory(pPhysicalAddress,
										  0x1000,
										  reinterpret_cast<PUCHAR>(ReadBuffer) + i * 0x1000);
			}
			else
			{
				// Last page, calculate the remaining size
				ULONG RemainingSize = static_cast<ULONG>(ReadSize - i * 0x1000);
				bRet = ReadPhysicalMemory(pPhysicalAddress,
										  RemainingSize,
										  reinterpret_cast<PUCHAR>(ReadBuffer) + i * 0x1000);
			}

			if (!bRet)
			{
				LOG("[-] ReadPhysicalMemory failed for physical address: " << reinterpret_cast<PUCHAR>(pPhysicalAddress));
				break;
			}
		}
	}


	return bRet;
}

BOOLEAN
BiosToolCommonDriver::KernelWrite(
	PVOID VirtualAddress,
	PVOID WriteBuffer,
	SIZE_T WriteSize)
{
	if (!VirtualAddress || !WriteBuffer || !WriteSize || !m_bInitialized)
	{
		LOG("[-] Invalid parameters for KernelWrite. VirtualAddress: " << VirtualAddress << ", WriteBuffer: " << WriteBuffer << ", WriteSize: " << WriteSize);
		if (!m_bInitialized)
		{
			LOG("[-] Ensure that the driver is initialized.");
		}
		return FALSE;
	}

	BOOLEAN bRet = FALSE;
	if (WriteSize <= 0x1000)
	{
		PVOID pPhysicalAddress = VirtualToPhysical(VirtualAddress);
		if (!pPhysicalAddress)
		{

			LOG("[-] Failed to translate virtual address to physical address using MemoryMap.");
			return FALSE;

		}

		bRet = WritePhysicalMemory(reinterpret_cast<PVOID>(pPhysicalAddress), static_cast<ULONG>(WriteSize), WriteBuffer);
	}
	else
	{
		// WriteSize > 0x1000, need to read page by page
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
				bRet = WritePhysicalMemory(pPhysicalAddress,
										   0x1000,
										   reinterpret_cast<PUCHAR>(WriteBuffer) + i * 0x1000);
			}
			else
			{
				// Last page, calculate the remaining size
				ULONG RemainingSize = static_cast<ULONG>(WriteSize - i * 0x1000);
				bRet = WritePhysicalMemory(pPhysicalAddress,
										   RemainingSize,
										   reinterpret_cast<PUCHAR>(WriteBuffer) + i * 0x1000);
			}

			if (!bRet)
			{
				LOG("[-] WritePhysicalMemory failed for physical address: " << reinterpret_cast<PUCHAR>(pPhysicalAddress));
				break;
			}
		}
	}

	return bRet;
}

BOOLEAN
BiosToolCommonDriver::ReadPhysicalMemory(
	PVOID PhysicalAddress,
	ULONG Size,
	PVOID ReadBuffer)
{
	if (!PhysicalAddress || !ReadBuffer || !Size)
	{
		return FALSE;
	}

	auto pCurrentDestination = static_cast<PUCHAR>(ReadBuffer);
	auto pCurrentPhysicalAddress = reinterpret_cast<PUCHAR>(PhysicalAddress);
	auto bRet{ FALSE };
	while (Size > 0)
	{
		const auto nPageOffset = reinterpret_cast<ULONG_PTR>(pCurrentPhysicalAddress) & 0xFFF;
		const auto nBytesToPageBoundary = 0x1000 - nPageOffset;
		const auto chunkSize = static_cast<ULONG>(min(Size, nBytesToPageBoundary));

		struct
		{
			PVOID	PhysicalAddress;
			ULONG	Size;
			ULONG	Padding; // Padding to align the PhysicalAddress on 8 bytes boundary
		}ReadRequest;

		ReadRequest.Size = chunkSize;
		ReadRequest.PhysicalAddress = pCurrentPhysicalAddress;
		ReadRequest.Padding = 0;

		unsigned char tempBuffer[0x1008] = { 0 };

		DWORD dwBytesReturned = 0;
		bRet = DeviceIoControl(m_hDevice,
							   IOCTL_READ_PHYSICAL,
							   &ReadRequest,
							   sizeof(ReadRequest),
							   tempBuffer,
							   sizeof(tempBuffer),
							   &dwBytesReturned,
							   nullptr);
		if (!bRet)
		{
			LOG("[-] Failed to read physical memory. Error code: " << GetLastError());
			return FALSE;
		}

		RtlCopyMemory(pCurrentDestination, tempBuffer + 8, chunkSize);


		pCurrentDestination += chunkSize;
		pCurrentPhysicalAddress += chunkSize;
		Size -= chunkSize;
	}


	return bRet;
}

BOOLEAN
BiosToolCommonDriver::WritePhysicalMemory(
	PVOID PhysicalAddress,
	ULONG Size,
	PVOID WriteBuffe)
{
	if (!PhysicalAddress || !WriteBuffe || !Size)
	{
		return FALSE;
	}

	struct
	{
		ULONG	Size;
		ULONG	Padding; // Padding to align the PhysicalAddress on 8 bytes boundary
		PUCHAR	Data;
		PVOID	PhysicalAddress;
	}WriteRequest;

	WriteRequest.Size = Size;
	WriteRequest.Data = (PUCHAR)WriteBuffe;
	WriteRequest.PhysicalAddress = PhysicalAddress;
	WriteRequest.Padding = 0;

	DWORD dwBytesReturned = 0;
	auto bRet = DeviceIoControl(m_hDevice,
								IOCTL_WRITE_PHYSICAL,
								&WriteRequest,
								sizeof(WriteRequest),
								&WriteRequest,
								sizeof(WriteRequest),
								&dwBytesReturned,
								nullptr);

	if (!bRet)
	{
		LOG("[-] Failed to write physical memory. Error code: " << GetLastError());
		return FALSE;
	}

	return bRet;
}

PVOID
BiosToolCommonDriver::VirtualToPhysical(PVOID VirtualAddress)
{
	if (!VirtualAddress)
	{
		return nullptr;
	}

	struct
	{
		PVOID	VirtualAddress;
		PVOID	PhysicalAddress;
	} Request;

	Request.VirtualAddress = VirtualAddress;

	DWORD dwBytesReturned = 0;
	auto bRet = DeviceIoControl(m_hDevice,
								IOCTL_VIRTUAL2PHYSICAL,
								&Request,
								sizeof(Request),
								&Request,
								sizeof(Request),
								&dwBytesReturned,
								nullptr);
	if (!bRet || 0 == Request.PhysicalAddress)
	{
		LOG("[-] Failed to translate virtual address to physical address. Error code: " << GetLastError());
		
		return Va2Pa(VirtualAddress);
	}

	return Request.PhysicalAddress;
}

HANDLE
BiosToolCommonDriver::CreateDevice(const char* DeviceName)
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
