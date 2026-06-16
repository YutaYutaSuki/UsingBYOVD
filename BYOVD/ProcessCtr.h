#pragma once
#include <windows.h>
#include <string>
#include "DriverService.hpp"
#include "Singleton.hpp"
#include "ObjectProxy.hpp"
#include "DriverKiller.hpp"
#include "ProcessCtrBin.hpp"

class ProcessCtr final :
	public DriverKiller<ProcessCtr>,
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

	BOOLEAN InitKiller() noexcept
	{
		return Initialize(ProcessCtrBin::hexData,
						  ProcessCtrBin::hexSize,
						  ProcessCtrBin::service,
						  ProcessCtrBin::serviceLength,
						  ProcessCtrBin::Key);
	}
	

	BOOLEAN
		KillProcess(ULONG Pid);

private:
	ProcessCtr() = default;
};



inline constexpr ObjectProxy<ProcessCtr> g_ProcessCtr{};

