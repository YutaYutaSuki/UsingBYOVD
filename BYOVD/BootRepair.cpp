#include "BootRepair.h"
#include "FileUtils.hpp"
#include "BootRepairBin.hpp"

BOOLEAN BootRepair::KillProcess(ULONG Pid)
{
	return DeviceIoControl(m_hDevice,
						   IOCTL_KILL_PROCESS,
						   &Pid,
						   sizeof(Pid),
						   nullptr,
						   0);

}
