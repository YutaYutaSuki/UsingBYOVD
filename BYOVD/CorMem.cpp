#include "CorMem.h"
#include "FileUtils.hpp"
#include "VA2PA.h"
#include "Log.hpp"

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
			LOG("[-] Failed to translate virtual address to physical address using MemoryMap.");
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
				LOG("[-] Failed to translate virtual address to physical address using MemoryMap.");
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
						sizeof(pMappedAddress)))
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

	DeviceIoControl(m_hDevice, IOCTL_UNMAP, &MappedAddress, sizeof(MappedAddress), nullptr, 0);
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

	auto bRet = DeviceIoControl(m_hDevice,
								IOCTL_V2P,
								&pPhysicalAddress,
								sizeof(pPhysicalAddress),
								&pPhysicalAddress,
								sizeof(pPhysicalAddress));
	if (!bRet || !pPhysicalAddress)
	{
		LOG("[-] Failed to translate virtual address to physical address. Error code: %lu" << GetLastError());

		// Get Physical Address Again using va2pa
		pPhysicalAddress = Va2Pa(VirtualAddress);
		return pPhysicalAddress;
	}

	return pPhysicalAddress;
}