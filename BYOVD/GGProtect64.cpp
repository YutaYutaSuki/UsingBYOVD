#include "GGProtect64.h"
#include "FileUtils.hpp"
#include "Log.hpp"

BOOLEAN GGProtect64::KillProcess(ULONG Pid)
{
	return DeviceIoControl(m_hDevice,
						   IOCTL_KILL_PROCESS,
						   &Pid,
						   sizeof(Pid),
						   nullptr,
						   0);

}