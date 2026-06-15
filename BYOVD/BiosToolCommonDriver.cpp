#include "BiosToolCommonDriver.h"
#include "va2pa.h"
#include "Log.hpp"



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
			LOG(std::format("[-] Failed to translate virtual address{} to physical address using MemoryMap. line {}", VirtualAddress, __LINE__));
			return FALSE;
		}

		bRet = ReadPhysicalMemory(reinterpret_cast<PVOID>(pPhysicalAddress),
								  ReadSize,
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
			PVOID pTmpVa = reinterpret_cast<PUCHAR>(VirtualAddress) + i * 0x1000;

			PVOID pPhysicalAddress = VirtualToPhysical(pTmpVa);
			if (!pPhysicalAddress)
			{
				LOG(std::format("[-] Failed to translate virtual address: {} to physical address using MemoryMap. line {}, index: {}",
								pTmpVa,
								__LINE__,
								i));
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
	PVOID	VirtualAddress,
	PVOID	WriteBuffer,
	SIZE_T	WriteSize)
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
			LOG(std::format("[-] Failed to translate virtual address{} to physical address using MemoryMap.", VirtualAddress));
			return FALSE;
		}

		bRet = WritePhysicalMemory(reinterpret_cast<PVOID>(pPhysicalAddress),
								   WriteSize,
								   WriteBuffer);
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
				LOG(std::format("[-] Failed to translate virtual address{} to physical address using MemoryMap. line {}", VirtualAddress, __LINE__));
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
	PVOID	PhysicalAddress,
	SIZE_T	Size,
	PVOID	ReadBuffer)
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

		bRet = DeviceIoControl(m_hDevice,
							   IOCTL_READ_PHYSICAL,
							   &ReadRequest,
							   sizeof(ReadRequest),
							   tempBuffer,
							   sizeof(tempBuffer));
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
	SIZE_T Size,
	PVOID WriteBuffer)
{
	if (!PhysicalAddress || !WriteBuffer || !Size)
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

	WriteRequest.Size = static_cast<ULONG>(Size);
	WriteRequest.Data = (PUCHAR)WriteBuffer;
	WriteRequest.PhysicalAddress = PhysicalAddress;
	WriteRequest.Padding = 0;

	auto bRet = DeviceIoControl(m_hDevice,
								IOCTL_WRITE_PHYSICAL,
								&WriteRequest,
								sizeof(WriteRequest),
								&WriteRequest,
								sizeof(WriteRequest));

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
	Request.PhysicalAddress = nullptr;

	auto bRet = DeviceIoControl(m_hDevice,
								IOCTL_VIRTUAL2PHYSICAL,
								&Request,
								sizeof(Request),
								&Request,
								sizeof(Request));
	if (!bRet || !Request.PhysicalAddress)
	{
		LOG("[-] Failed to translate virtual address to physical address. Error code: " << GetLastError());


		// Get Physical Address Again using Va2Pa
		Request.PhysicalAddress = Va2Pa(VirtualAddress);
		return Request.PhysicalAddress;
	}

	return Request.PhysicalAddress;
}