#include "ProcessCtr.h"
#include "FileUtils.hpp"
#include "Log.hpp"

BOOLEAN ProcessCtr::KillProcess(ULONG Pid)
{
	DWORD dwRead{ 0 };

	return DeviceIoControl(m_hDevice,
						   IOCTL_KILL_PROCESS,
						   &Pid,
						   sizeof(Pid),
						   nullptr,
						   0);

}
