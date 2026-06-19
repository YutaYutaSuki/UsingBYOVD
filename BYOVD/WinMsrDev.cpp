#include "WinMsrDev.h"
#include "va2pa.h"

typedef struct  _INPUT_BUFFER_READ
{
	PVOID PhysicalAddress;
	ULONG AlignNumer;
	ULONG AlignSize;
}INPUT_BUFFER_READ, * PINPUT_BUFFER_READ;

typedef struct  _INPUT_BUFFER_WRITE
{
	PVOID	PhysicalAddress;
	ULONG	AlignNumer;
	ULONG	AlignSize;
	BYTE    Data[ANYSIZE_ARRAY];
}INPUT_BUFFER_WRITE, * PINPUT_BUFFER_WRITE;


BOOLEAN
WinMsrDev::KernelRead(
	PVOID	VirtualAddress,
	PVOID	ReadBuffer,
	SIZE_T	ReadSize)
{
	if (!VirtualAddress || !ReadBuffer || !ReadSize || !m_bInitialized)
	{
		return FALSE;
	}

	BOOLEAN bRet{ FALSE };

	if (ReadSize <= 0x1000)
	{
		PVOID pPhysicalAddress = VirtualToPhysical(VirtualAddress);
		if (!pPhysicalAddress)
		{
			//std::cout << "[-] VirtualToPhysical failed for address: " << VirtualAddress << std::endl;
			LOG("[-] VirtualToPhysical failed for address: " << VirtualAddress);
			return FALSE;
		}


		bRet = ReadPhysicalMemory(reinterpret_cast<PVOID>(pPhysicalAddress), ReadSize, ReadBuffer);
		if (!bRet)
		{
			//std::cout << "[-] ReadPhysicalMemory failed for physical address:" << pPhysicalAddress << "" << std::endl;
			LOG("[-] ReadPhysicalMemory failed for physical address: " << pPhysicalAddress);
		}
	}
	else
	{
		// ReadSize > 0x1000 , read page by page
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
WinMsrDev::KernelWrite(
	PVOID	VirtualAddress,
	PVOID	WriteBuffer,
	SIZE_T	WriteSize)
{
	if (!VirtualAddress || !WriteBuffer || !WriteSize || !m_bInitialized)
	{
		return FALSE;
	}

	BOOLEAN bRet{ FALSE };

	if (WriteSize <= 0x1000)
	{
		PVOID pPhysicalAddress = VirtualToPhysical(VirtualAddress);
		if (!pPhysicalAddress)
		{
			LOG("[-] VirtualToPhysical failed for address: " << VirtualAddress);
			return FALSE;
		}

		bRet = WritePhysicalMemory(reinterpret_cast<PVOID>(pPhysicalAddress), WriteSize, WriteBuffer);
	}
	else
	{
		// WriteSize > 0x1000, need to write page by page
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
WinMsrDev::ReadPhysicalMemory(
	PVOID	PhysicalAddress,
	SIZE_T	Size,
	PVOID	ReadBuffer)
{
	BOOLEAN bRet = FALSE;

	if (INVALID_HANDLE_VALUE == m_hDevice)
	{
		return FALSE;
	}

	INPUT_BUFFER_READ InputBuffer{ 0 };
	InputBuffer.PhysicalAddress = PhysicalAddress;
	InputBuffer.AlignNumer		= 1;
	InputBuffer.AlignSize		= static_cast<ULONG>(Size);


	bRet = DeviceIoControl(m_hDevice,
						   IOCTL_READ_PHYSICAL,
						   &InputBuffer,
						   sizeof(InputBuffer),
						   ReadBuffer,
						   InputBuffer.AlignSize);
	if (!bRet)
	{
		LOG("[-] DeviceIoControl failed with error code: " << GetLastError());
	}

	return bRet;

}

BOOLEAN
WinMsrDev::WritePhysicalMemory(
	PVOID	PhysicalAddress,
	SIZE_T	Size,
	PVOID	WriteBuffe)
{
	BOOLEAN bRet = FALSE;

	if (INVALID_HANDLE_VALUE == m_hDevice)
	{
		return FALSE;
	}

	ULONG InputBufferSize = static_cast<ULONG>(sizeof(INPUT_BUFFER_WRITE) + Size);

	PINPUT_BUFFER_WRITE InputBuffer = (PINPUT_BUFFER_WRITE)HeapAlloc(GetProcessHeap(),
																	 HEAP_ZERO_MEMORY,
																	 InputBufferSize);
	if (!InputBuffer)
	{
		std::cout << "[-] HeapAlloc failed for InputBuffer" << std::endl;
		return FALSE;
	}

	InputBuffer->PhysicalAddress = PhysicalAddress;
	InputBuffer->AlignNumer		 = 1;
	InputBuffer->AlignSize		 = static_cast<ULONG>(Size);
	memcpy(InputBuffer->Data, WriteBuffe, Size);

	DWORD dwBytesReturned = 0;

	bRet = DeviceIoControl(m_hDevice,
						   IOCTL_WRITE_PHYSICAL,
						   InputBuffer,
						   InputBufferSize,
						   nullptr,
						   0);
	if (!bRet)
	{
		//std::cout << "[-] DeviceIoControl failed with error code: " << GetLastError() << std::endl;
		LOG("[-] DeviceIoControl failed with error code: " << GetLastError());
	}


	HeapFree(GetProcessHeap(), 0, InputBuffer);


	return bRet;
}

PVOID
WinMsrDev::VirtualToPhysical(
	PVOID VirtualAddress)
{
	return Va2Pa(VirtualAddress);
}