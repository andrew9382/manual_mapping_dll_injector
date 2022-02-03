#pragma once

#define RELOC_FLAG64(rel_info) ((rel_info >> 12) == IMAGE_REL_BASED_DIR64)
#define RELOC_FLAG32(rel_info) ((rel_info >> 12) == IMAGE_REL_BASED_HIGHLOW)

#ifdef _WIN64
#define RELOC_FLAG RELOC_FLAG64
#else
#define RELOC_FLAG RELOC_FLAG32
#endif

using f_DLL_ENTRY_POINT = BOOL (WINAPI*) (HINSTANCE hDll, DWORD dwReason, HINSTANCE pReserved);

struct MANUAL_MAPPING_SHELL_DATA
{
	HANDLE			h_proc = 0;
	wchar_t			dll_path[MAX_PATH] = { 0 };
	DWORD			flags = 0;

	MANUAL_MAP_FUNCTION_TABLE f_table;

	MANUAL_MAPPING_SHELL_DATA(INJECTION_DATA* data);
};

struct MANUAL_MAP_FUNCTION_TABLE
{
	FUNC_DUMMY(LdrGetProcedureAddress);
	FUNC_DUMMY(LdrLoadDll);
	FUNC_DUMMY(RtlFreeHeap);
	FUNC_DUMMY(LdrpHeap);
	FUNC_DUMMY(RtlAllocateHeap);
	FUNC_DUMMY(NtAllocateVirtualMemory);
	FUNC_DUMMY(NtFreeVirtualMemory);
	FUNC_DUMMY(memmove);
	FUNC_DUMMY(NtOpenFile);
	FUNC_DUMMY(NtClose);
	FUNC_DUMMY(NtSetInformationFile);
	FUNC_DUMMY(NtQueryInformationFile);
	FUNC_DUMMY(NtReadFile);
	FUNC_DUMMY(LdrLockLoaderLock);
	FUNC_DUMMY(LdrUnlockLoaderLock);

	void* p_LdrpHeap = nullptr;

	MANUAL_MAP_FUNCTION_TABLE();
};

DWORD __stdcall CODE_SEG(".mmap_seg$1") ManualMapShell(MANUAL_MAPPING_SHELL_DATA* mp_data);
DWORD __stdcall CODE_SEG(".mmap_seg$2") ManualMapShellEnd();