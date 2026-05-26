#pragma once
#include "SuperFetch.h"

inline PVOID Va2Pa(PVOID VirtualAddress);

inline PVOID Va2Pa(PVOID VirtualAddress)
{
	auto res = spf::memory_map::current();

	if (res.has_value())
	{
		auto mm = res.value();
		return reinterpret_cast<PVOID>(mm.translate(VirtualAddress));
	}
	return 0;
}
