#include "DriverWorker.hpp"
#include "Log.hpp"

auto
DriverWorker::InitializeDriver() -> BOOLEAN
{
	return g_PGRHostControl->Initialize();
}

auto
DriverWorker::UninitializeDriver() -> VOID
{
	g_PGRHostControl->Uninitialize();
}

auto 
DriverWorker::Read(
	PVOID VirtualAddress,
	PVOID ReadBuffer, 
	ULONG Size) ->BOOLEAN
{
	return g_PGRHostControl->Read(VirtualAddress, ReadBuffer, Size);
}

auto 
DriverWorker::Write(
	PVOID VirtualAddress, 
	PVOID WriteBuffer,
	ULONG Size) ->BOOLEAN
{
	return g_PGRHostControl->Write(VirtualAddress, WriteBuffer, Size);
}

auto DriverWorker::Kill(ULONG Pid) ->BOOLEAN
{
	auto bResut = g_BootRepair->Initialize();
	if (!bResut)
	{
		return FALSE;
	}
	else
	{
		LOG("Start BootRepair Driver");
	}

	if (Pid > 4)
	{
		//LOG("Kill pid = ") << Pid << std::endl;;
		bResut = g_BootRepair->KillProcess(Pid);

	}

	g_BootRepair->Uninitialize();
	return bResut;
}
