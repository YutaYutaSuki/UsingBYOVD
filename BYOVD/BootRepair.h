#pragma once
#include <windows.h>
#include <string>
#include "DriverProvider.hpp"
#include "DriverService.hpp"
#include "Singleton.hpp"
#include "ObjectProxy.hpp"

class BootRepair final :
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

	BOOLEAN Initialize() noexcept;
	VOID Uninitialize();

	BOOLEAN
		KillProcess(ULONG Pid);

private:
	BootRepair() = default;

private:
	HANDLE CreateDevice();

private:
	HANDLE			m_hDevice{ INVALID_HANDLE_VALUE };
	BOOLEAN			m_bInitialized{ FALSE };
	DriverService*  m_pDriverService{ nullptr };
};



inline constexpr ObjectProxy<BootRepair> g_BootRepair{};

