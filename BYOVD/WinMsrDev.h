#pragma once
#include <windows.h>
#include <string>
#include "DriverProvider.hpp"
#include "DriverService.hpp"
#include "Singleton.hpp"
#include "ObjectProxy.hpp"
#include "WinMsrDevBin.hpp"

class WinMsrDev final :
	public DriverProvider<WinMsrDev>,
	public Singleton<WinMsrDev>
{
	friend class Singleton<WinMsrDev>;
private:
	static constexpr ULONG IOCTL_READ_PHYSICAL		= 0x9C406104u;
	static constexpr ULONG IOCTL_WRITE_PHYSICAL		= 0x9C40A108u;
	
public:
	explicit WinMsrDev(Token) noexcept : WinMsrDev()
	{
	}
	~WinMsrDev() = default;

	BOOLEAN InitDriver() noexcept
	{
		return Initialize(WinMsrDevBin::hexData,
						  WinMsrDevBin::hexSize,
						  WinMsrDevBin::service,
						  WinMsrDevBin::serviceSize,
						  WinMsrDevBin::Key);
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
	WinMsrDev() = default;

private:
	BOOLEAN
		ReadPhysicalMemory(
			PVOID	PhysicalAddress,
			SIZE_T	Size,
			PVOID	ReadBuffer);

	BOOLEAN
		WritePhysicalMemory(
			PVOID	PhysicalAddress,
			SIZE_T	Size,
			PVOID	WriteBuffe);

	PVOID
		VirtualToPhysical(PVOID VirtualAddress);

};

inline constexpr ObjectProxy<WinMsrDev> g_WinMsrDev{};