#pragma once
#include <windows.h>
#include <string>
#include "DriverProvider.hpp"
#include "DriverService.hpp"
#include "Singleton.hpp"
#include "ObjectProxy.hpp"
#include "BiosToolCommonDriverBin.hpp"

class BiosToolCommonDriver final : 
	public DriverProvider<BiosToolCommonDriver>,
	public Singleton<BiosToolCommonDriver>
{
	friend class Singleton<BiosToolCommonDriver>;
private:
	static constexpr ULONG IOCTL_READ_PHYSICAL		= 0x22202Cu;
	static constexpr ULONG IOCTL_WRITE_PHYSICAL		= 0x222030u;
	static constexpr ULONG IOCTL_VIRTUAL2PHYSICAL	= 0x222034u;
public:
	explicit BiosToolCommonDriver(Token) noexcept : BiosToolCommonDriver()
	{
	}	
	~BiosToolCommonDriver() = default;
	
	BOOLEAN InitDriver() noexcept
	{
		return Initialize(BiosToolCommonDriverBin::hexData,
						  BiosToolCommonDriverBin::hexDataSize,
						  BiosToolCommonDriverBin::service,
						  BiosToolCommonDriverBin::serviceLength,
						  BiosToolCommonDriverBin::Key);
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
	BiosToolCommonDriver() = default;

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

inline constexpr ObjectProxy<BiosToolCommonDriver> g_BiosToolCommonDriver{};