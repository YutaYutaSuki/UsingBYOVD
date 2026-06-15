#pragma once
#include <windows.h>
#include <string>
#include "DriverProvider.hpp"
#include "DriverService.hpp"
#include "Singleton.hpp"
#include "CorMemBin.hpp"

class CorMem final :
	public DriverProvider<CorMem>,
	public Singleton<CorMem>
{
	friend class Singleton<CorMem>;

private:
	static constexpr ULONG IOCTL_MAP = 0x22200Cu;
	static constexpr ULONG IOCTL_UNMAP = 0x222010u;
	static constexpr ULONG IOCTL_V2P = 0x22201Cu;

public:
	explicit CorMem(Token) noexcept : CorMem()
	{
	}
	~CorMem() = default;

	BOOLEAN InitDriver() noexcept
	{
		return Initialize(CorMemBin::hexData,
						  CorMemBin::HexDataSize,
						  CorMemBin::service,
						  CorMemBin::serviceLength,
						  CorMemBin::Key);
	}


	BOOLEAN
		KernelRead(PVOID	VirtualAddress,
				   PVOID	ReadBuffer,
				   SIZE_T	ReadSize);

	BOOLEAN
		KernelWrite(PVOID	VirtualAddress,
					PVOID	WriteBuffer,
					SIZE_T	WriteSize);

private:
	CorMem() = default;

private:
	PVOID
		MapPhysicalMemory(
			PVOID	PhysicalAddress,
			SIZE_T	Size);

	VOID
		UnmapPhysicalMemory(PVOID MappedAddress);

	PVOID
		VirtualToPhysical(PVOID VirtualAddress);
};

inline constexpr ObjectProxy<CorMem> g_CorMem{};