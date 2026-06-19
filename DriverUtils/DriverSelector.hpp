#pragma once
#include <windows.h>
#include <any>

// RX Driver
#include "CorMem.h"
#include "PGRHostControl.h"
#include "BiosToolCommonDriver.h"
#include "WinMsrDev.h"

// Killer
#include "BootRepair.h"
#include "ProcessCtr.h"
#include "GGProtect64.h"

namespace KillerSelector
{
	enum class KillerType
	{
		BootRepair,
		ProcessCtr,
		GGProtect64
	};
	static std::any Killers[] = {
		std::any(std::addressof(BootRepair::Instance())),
		std::any(std::addressof(ProcessCtr::Instance())),
		std::any(std::addressof(GGProtect64::Instance()))

	};
	template <KillerType _Type>
	struct GetKillerImpl
	{
	};

	template <>
	struct GetKillerImpl<KillerType::BootRepair>
	{
		using Type = std::add_pointer_t<BootRepair>;
	};

	template <>
	struct GetKillerImpl<KillerType::ProcessCtr>
	{
		using Type = std::add_pointer_t<ProcessCtr>;
	};

	template <>
	struct GetKillerImpl<KillerType::GGProtect64>
	{
		using Type = std::add_pointer_t<GGProtect64>;
	};

	template <KillerType _Type>
	auto GetKiller()
	{
		return std::any_cast<GetKillerImpl<_Type>::Type>(Killers[static_cast<int>(_Type)]);
	}
}

using KillerType = KillerSelector::KillerType;
using KillerSelector::GetKiller;

#define		_KILL_PROVIDER KillerType::ProcessCtr
#define		CurrentKiller() GetKiller<_KILL_PROVIDER>()


namespace DriverWorker
{
	enum class ProviderType
	{
		CorMem,
		PGRHostControl,
		BiosToolCommonDriver,
		WinMsrDev
	};

	static std::any Providers[] = {
		std::any(std::addressof(CorMem::Instance())),
		std::any(std::addressof(PGRHostControl::Instance())),
		std::any(std::addressof(BiosToolCommonDriver::Instance())),
		std::any(std::addressof(WinMsrDev::Instance()))
	};

	template <ProviderType _Type>
	struct GetProviderImpl {};

	template <>
	struct GetProviderImpl<ProviderType::CorMem>
	{
		using Type = std::add_pointer_t<CorMem>;
	};

	template <>
	struct GetProviderImpl<ProviderType::PGRHostControl>
	{
		using Type = std::add_pointer_t<PGRHostControl>;
	};

	template <>
	struct GetProviderImpl<ProviderType::BiosToolCommonDriver>
	{
		using Type = std::add_pointer_t<BiosToolCommonDriver>;
	};

	template <>
	struct GetProviderImpl<ProviderType::WinMsrDev>
	{
		using Type = std::add_pointer_t<WinMsrDev>;
	};

	template <ProviderType _Type>
	auto GetProvider()
	{
		return std::any_cast<GetProviderImpl<_Type>::Type>(Providers[static_cast<int>(_Type)]);
	}
}

using ProviderType = DriverWorker::ProviderType;

using DriverWorker::GetProvider;

// Change this to switch to different provider
#define _USE_PROVIDER ProviderType::BiosToolCommonDriver

#define CurrentProvider() GetProvider<_USE_PROVIDER>()