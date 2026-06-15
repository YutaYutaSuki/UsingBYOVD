#pragma once
#include <windows.h>
#include <string>
#include "DriverService.hpp"
#include "Singleton.hpp"
#include "ObjectProxy.hpp"

class GGProtect64 final :
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

	BOOLEAN Initialize() noexcept;
	VOID Uninitialize();

	BOOLEAN
		KillProcess(ULONG Pid);

private:
	GGProtect64() = default;

private:
	HANDLE CreateDevice();

private:
	HANDLE			m_hDevice{ INVALID_HANDLE_VALUE };
	BOOLEAN			m_bInitialized{ FALSE };
	DriverService* m_pDriverService{ nullptr };
};



inline constexpr ObjectProxy<GGProtect64> g_GGProtect64{};