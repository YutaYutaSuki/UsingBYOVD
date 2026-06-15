#pragma once
#include <windows.h>
#include <string>
#include "DriverService.hpp"
#include "Singleton.hpp"
#include "ObjectProxy.hpp"

class ProcessCtr final :
	public Singleton<ProcessCtr>
{
	friend class Singleton<ProcessCtr>;

private:
	static constexpr ULONG IOCTL_KILL_PROCESS = 0x89DB202Cu;

public:
	explicit ProcessCtr(Token) noexcept : ProcessCtr()
	{
	}
	~ProcessCtr() = default;

	BOOLEAN Initialize() noexcept;
	VOID Uninitialize();

	BOOLEAN
		KillProcess(ULONG Pid);

private:
	ProcessCtr() = default;

private:
	HANDLE CreateDevice();

private:
	HANDLE			m_hDevice{ INVALID_HANDLE_VALUE };
	BOOLEAN			m_bInitialized{ FALSE };
	DriverService*  m_pDriverService{ nullptr };
};



inline constexpr ObjectProxy<ProcessCtr> g_ProcessCtr{};

