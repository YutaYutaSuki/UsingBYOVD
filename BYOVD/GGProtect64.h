#pragma once
#include <windows.h>
#include <string>
#include "DriverService.hpp"
#include "Singleton.hpp"
#include "ObjectProxy.hpp"
#include "GGProtect64Bin.hpp"
#include "DriverKiller.hpp"

class GGProtect64 final :
	public DriverKiller<GGProtect64>,
	public Singleton<GGProtect64>
{
	friend class Singleton<GGProtect64>;

private:
	static constexpr ULONG IOCTL_KILL_PROCESS  = 0x223C04u;
	static constexpr ULONG IOCTL_DRIVER_LOAD   = 0x223C14u;
	static constexpr ULONG IOCTL_DRIVER_UNLOAD = 0x223C1Cu;

	static constexpr ULONG CHECK_VALUE = 0x5A84;
public:
	explicit GGProtect64(Token) noexcept : GGProtect64()
	{
	}
	~GGProtect64() = default;

	BOOLEAN InitKiller() noexcept
	{
		return Initialize(GGProtect64Bin::hexData,
						  GGProtect64Bin::hexSize,
						  GGProtect64Bin::service,
						  GGProtect64Bin::serviceSize,
						  GGProtect64Bin::Key);
	}

	BOOLEAN
		KillProcess(ULONG Pid);

private:
	GGProtect64() = default;
};



inline constexpr ObjectProxy<GGProtect64> g_GGProtect64{};