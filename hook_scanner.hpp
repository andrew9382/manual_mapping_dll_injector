#pragma once

#define SCAN_BYTES_COUNT 0x10

static const wchar_t* modules[] =
{
	L"kernel32.dll",
	L"ntdll.dll"
};

static const char* to_hk_scan[] =
{
	"NtQueryObject",
	"LdrGetProcedureAddress",
	"LdrLoadDll",
	"LdrUnloadDll",
	"RtlFreeHeap",
	"RtlAllocateHeap",
	"NtAllocateVirtualMemory",
	"NtFreeVirtualMemory",
	"memmove",
	"NtOpenFile",
	"NtSetInformationFile",
	"NtClose",
	"NtSetInformationFile",
	"NtQueryInformationFile",
	"NtReadFile",
	"LdrLockLoaderLock",
	"LdrUnlockLoaderLock",

	"LoadLibraryA",
	"FreeLibrary"
};

enum class HOOK_RESTORE_MODE
{
	HRM_RESTORE_ORIG,
	HRM_RESTORE_HOOK
};

struct HOOK_SCAN_DATA
{
	BYTE			orig_bytes[SCAN_BYTES_COUNT]	= { 0 };
	BYTE			remote_bytes[SCAN_BYTES_COUNT]	= { 0 };
	std::string		func_name						= { 0 };
	void*			func_addr						= 0;
	bool			hooked							= false;
};

bool HookScanAndPatch(std::vector<HOOK_SCAN_DATA>* hk_vec, HANDLE h_proc);
bool CompareFuncs(std::vector<HOOK_SCAN_DATA>* hk_vec);
bool RestoreHookedFuncs(std::vector<HOOK_SCAN_DATA>* hk_vec, HANDLE h_proc, HOOK_RESTORE_MODE mode);