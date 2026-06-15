#pragma once
#include <windows.h>
#include <string>
#include "DriverProvider.hpp"
#include "DriverService.hpp"
#include "Singleton.hpp"
#include "ObjectProxy.hpp"
#include "PGRHostControlBin.hpp"

typedef struct _MapRequest
{
	SIZE_T	Size;
	PVOID	PhysicalAddress;
	PVOID	Handle;
	PVOID	MappingAddress;
	PVOID	SectionObject;
} MapRequest, * PMapRequest;


class PGRHostControl final :
	public DriverProvider<PGRHostControl>,
	public Singleton<PGRHostControl>
{
	friend class Singleton<PGRHostControl>;

private:
	static constexpr ULONG IOCTL_MAP	= 0x80102040u;
	static constexpr ULONG IOCTL_UNMAP	= 0x80102044u;

public:
	explicit PGRHostControl(Token) noexcept : PGRHostControl()
	{
	}
	~PGRHostControl() = default;

	BOOLEAN InitDriver() noexcept
	{
		return Initialize(PGRHostControlBin::hexData,
						  PGRHostControlBin::hexSize,
						  PGRHostControlBin::service,
						  PGRHostControlBin::serviceLength,
						  PGRHostControlBin::Key);
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
	PGRHostControl() = default;

private:
	PVOID
		MapPhysicalMemory(
			PMapRequest Request);

	VOID
		UnmapPhysicalMemory(PMapRequest Request);

	PVOID
		VirtualToPhysical(PVOID VirtualAddress);
};



inline constexpr ObjectProxy<PGRHostControl> g_PGRHostControl{};