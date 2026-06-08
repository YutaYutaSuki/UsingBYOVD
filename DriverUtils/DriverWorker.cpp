#include "DriverWorker.hpp"
#include "Log.hpp"

static BOOLEAN g_bKiller{FALSE};

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

auto DriverWorker::KillerInit()->BOOLEAN
{
	//auto bResut = g_BootRepair->Initialize();
	//if (!bResut)
	//{
	//	return FALSE;
	//}
	//else
	//{
	//	LOG("Start BootRepair Driver");
	//  g_bKiller = TRUE;
	//}

	auto bResut = g_GGProtect64->Initialize();
	if (!bResut)
	{
		return FALSE;
	}
	else
	{
		LOG("Start Killer Driver");
		g_bKiller = TRUE;
	}

	return FALSE;
}



auto DriverWorker::Kill(ULONG Pid) ->BOOLEAN
{

	//if (Pid > 4)
	//{
	//	//LOG("Kill pid = ") << Pid << std::endl;;
	//	bResut = g_BootRepair->KillProcess(Pid);

	//}

	//return bResut;

	auto bResult{ FALSE };

	// check it again
	if (!g_bKiller)
	{
		return FALSE;
	}

	if (Pid > 4)
	{
		//LOG("Kill pid = ") << Pid << std::endl;;
		bResult = g_GGProtect64->KillProcess(Pid);

	}

	// unload will cause BSOD
	// never call it like this
	//g_GGProtect64->Uninitialize();
	return bResult;
}

auto DriverWorker::KillUnInit()
{
	if (!g_bKiller)
	{
		return;
	}
	//g_GGProtect64->Uninitialize();

	//g_BootRepair->Uninitialize();
}
