#include "KernelUtils.hpp"
#include "Utils.hpp"
#include <filesystem>
#include <fstream>


using namespace Utils;

typedef struct _RTL_PROCESS_MODULE_INFORMATION
{
	HANDLE Section;
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES
{
	ULONG NumberOfModules;
	RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;


PVOID 
KernelUtils::GetKernelModuleBase(const std::string& KernelModuleName) const
{
	PVOID pBuffer{ nullptr };

	NTSTATUS status{ STATUS_SUCCESS };
	DWORD dwBufferSize{ 0 };

	// Query System Module Information
	status = Utils::NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)SystemModuleInformation,
											 nullptr,
											 0,
											 &dwBufferSize);
	while (status == STATUS_INFO_LENGTH_MISMATCH)
	{
		if (!pBuffer)
		{
			HeapFree(GetProcessHeap(), 0, pBuffer);
		}

		pBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwBufferSize);

		status = Utils::NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)SystemModuleInformation,
												 pBuffer,
												 dwBufferSize,
												 &dwBufferSize);
	}
	if (!NT_SUCCESS(status) || !pBuffer)
	{
		if (pBuffer)
		{
			HeapFree(GetProcessHeap(), 0, pBuffer);
		}
		return nullptr;
	}

	PVOID pReturn{ nullptr };

	const auto pModuleInfo = reinterpret_cast<PRTL_PROCESS_MODULES>(pBuffer);
	for (auto i{ 0u }; i != pModuleInfo->NumberOfModules; ++i)
	{
		const auto pName = reinterpret_cast<char*>(pModuleInfo->Modules[i].FullPathName) + pModuleInfo->Modules[i].OffsetToFileName;
		if (0 == _stricmp(pName, KernelModuleName.c_str()))
		{
			pReturn = pModuleInfo->Modules[i].ImageBase;
			break;
		}
	}

	if (pBuffer)
	{
		HeapFree(GetProcessHeap(), 0, pBuffer);
	}

	return pReturn;
}

std::map<std::string, DWORD> 
KernelUtils::GetExportFunctionOffsetCache()
{
	if (!m_mapOfExportOffsetsCache.empty())
	{
		return m_mapOfExportOffsetsCache;
	}

	wchar_t dir[MAX_PATH] = {};
	GetSystemDirectoryW(dir, MAX_PATH);
	auto path = std::filesystem::path(dir) / L"ntoskrnl.exe";

	std::ifstream readFile(path, std::ios::binary | std::ios::in);
	if (!readFile.is_open())
	{
		LOG("[-] Failed to open file: " << path << std::endl);
		return {};
	}


	readFile.seekg(0, std::ios::end);
	if (readFile.fail())
	{
		LOG("[-] Failed to seek to end of file" << std::endl);
		return {};
	}

	const auto size = static_cast<size_t>(readFile.tellg());
	if (size == 0 || size == static_cast<size_t>(-1))
	{
		LOG("[-] Invalid file size" << std::endl);
		return {};
	}

	readFile.seekg(0, std::ios::beg);
	if (readFile.fail())
	{
		LOG("[-] Failed to seek to beginning" << std::endl);
		return {};
	}

	std::vector<std::byte> ImageBuffer(size);

	readFile.read(reinterpret_cast<char*>(ImageBuffer.data()), size);

	if (!readFile)
	{
		LOG("[-] Failed to read file content. Only read "
			<< readFile.gcount() << " bytes." << std::endl);
		return {};
	}


	if (ImageBuffer.size() < sizeof(IMAGE_DOS_HEADER))
	{
		return {};
	}

	const auto* pDosHdr = reinterpret_cast<const IMAGE_DOS_HEADER*>(ImageBuffer.data());
	if (pDosHdr->e_magic != IMAGE_DOS_SIGNATURE)
	{
		return {};
	}
	const auto* pNtHdr = reinterpret_cast<const IMAGE_NT_HEADERS*>(ImageBuffer.data() + pDosHdr->e_lfanew);
	if (pNtHdr->Signature != IMAGE_NT_SIGNATURE)
	{
		return {};
	}
	const auto nNumberOfSections = pNtHdr->FileHeader.NumberOfSections;

	auto Section = IMAGE_FIRST_SECTION(pNtHdr);

	auto RvaToRawOffset = [&](ULONG Rva) -> ULONG
	{

		for (USHORT i = 0; i < nNumberOfSections; ++i)
		{
			if (Rva >= Section->VirtualAddress &&
				Rva < Section->VirtualAddress + Section->Misc.VirtualSize)
			{
				return Section->PointerToRawData + (Rva - Section->VirtualAddress);
			}
			++Section;
		}
		return 0;

	};


	const auto tmp = pNtHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	if (tmp.VirtualAddress == 0 ||
		tmp.Size == 0)
	{
		return {};
	}

	ULONG nExportRaw = RvaToRawOffset(tmp.VirtualAddress);

	const auto* exp		 = reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(ImageBuffer.data() + nExportRaw);
	const auto* names	 = reinterpret_cast<const DWORD*>(ImageBuffer.data() + RvaToRawOffset(exp->AddressOfNames));
	const auto* ordinals = reinterpret_cast<const WORD*>(ImageBuffer.data() + RvaToRawOffset(exp->AddressOfNameOrdinals));
	const auto* funcs	 = reinterpret_cast<const DWORD*>(ImageBuffer.data() + RvaToRawOffset(exp->AddressOfFunctions));

	for (DWORD i = 0; i < exp->NumberOfNames; ++i)
	{
		std::string funcName{ reinterpret_cast<const char*>(ImageBuffer.data() + RvaToRawOffset(names[i])) };
		m_mapOfExportOffsetsCache.insert({ funcName, funcs[ordinals[i]] });
	}

	return m_mapOfExportOffsetsCache;
}
