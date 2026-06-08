#pragma once
#include "BiosToolCommonDriver.h"
#include "CorMem.h"
#include "BootRepair.h"
#include "PGRHostControl.h"
#include "GGProtect64.h"


namespace DriverWorker
{
	auto InitializeDriver()->BOOLEAN;

	VOID UninitializeDriver();

	auto Read(PVOID VirtualAddress, PVOID ReadBuffer, ULONG Size)->BOOLEAN;

	auto Write(PVOID VirtualAddress, PVOID WriteBuffer, ULONG Size)->BOOLEAN;

	auto KillerInit()->BOOLEAN;

	auto Kill(ULONG Pid)->BOOLEAN;

	auto KillUnInit();
}

