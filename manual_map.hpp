#pragma once

#define RELOC_FLAG64(rel_info) ((rel_info >> 12) == IMAGE_REL_BASED_DIR64)
#define RELOC_FLAG32(rel_info) ((rel_info >> 12) == IMAGE_REL_BASED_HIGHLOW)

#ifdef _WIN64
#define RELOC_FLAG RELOC_FLAG64
#else
#define RELOC_FLAG RELOC_FLAG32
#endif

using f_DLL_ENTRY_POINT  = BOOL     (WINAPI*) (HINSTANCE hDll, DWORD dwReason, HINSTANCE pReserved);

struct MANUAL_MAP_FUNCTION_TABLE
{
	NT_LOCAL(LdrGetProcedureAddress);
	//NT_LOCAL(LdrLoadDll);
	//NT_LOCAL(LdrUnloadDll);
	NT_LOCAL(RtlFreeHeap);
	NT_LOCAL(LdrpHeap);
	NT_LOCAL(RtlAllocateHeap);
	NT_LOCAL(NtAllocateVirtualMemory);
	NT_LOCAL(NtFreeVirtualMemory);
	NT_LOCAL(memmove);
	NT_LOCAL(NtOpenFile);
	NT_LOCAL(NtClose);
	NT_LOCAL(NtSetInformationFile);
	NT_LOCAL(NtQueryInformationFile);
	NT_LOCAL(NtReadFile);
	NT_LOCAL(LdrLockLoaderLock);
	NT_LOCAL(LdrUnlockLoaderLock);

	WIN32_LOCAL(LoadLibraryA); // used temporary
	WIN32_LOCAL(FreeLibrary); // used temporary

	void* p_LdrpHeap = nullptr;

	MANUAL_MAP_FUNCTION_TABLE();
};

struct MANUAL_MAPPING_SHELL_DATA
{
	HMODULE			out_module_base		= 0;
	wchar_t         dll_path[MAX_PATH]  = { 0 };
	DWORD			flags				= 0;

	MANUAL_MAP_FUNCTION_TABLE f_table;

	MANUAL_MAPPING_SHELL_DATA(INJECTION_DATA* data);
};


struct MM_DEPENDENCY_RECORD
{
	struct MM_DEPENDENCY_RECORD* f_link;

	HMODULE h_dll;
};

DWORD CODE_SEG(".mmap_seg$1") __stdcall ManualMapShell(MANUAL_MAPPING_SHELL_DATA* mp_data);
DWORD CODE_SEG(".mmap_seg$2") __stdcall ManualMapShellEnd();