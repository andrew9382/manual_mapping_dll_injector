#pragma once

#define UNLINK_IF(e) if (e.Flink && e.Blink) { e.Flink->Blink = e.Blink; e.Blink->Flink = e.Flink; }

struct INJECT_INTERNAL_FUNCTION_TABLE
{
	NT_LOCAL(RtlRbRemoveNode);
	NT_LOCAL(LdrpModuleBaseAddressIndex);
	NT_LOCAL(LdrpMappingInfoIndex);
	NT_LOCAL(NtProtectVirtualMemory);
	NT_LOCAL(memmove);
	NT_LOCAL(memset);
	
	WIN32_LOCAL(LoadLibraryExW);
	WIN32_LOCAL(FreeLibrary);
	WIN32_LOCAL(GetLastError);

	INJECT_INTERNAL_FUNCTION_TABLE();
};

struct INJECT_INTERNAL_DATA
{
	HMODULE		h_dll_out			= 0;
	DWORD		flags				= 0;
	DWORD		last_error			= 0;
	DWORD		os_version			= 0;
	DWORD		os_build_version	= 0; 
	wchar_t		dll_path[MAX_PATH]	= { 0 };

	INJECT_INTERNAL_FUNCTION_TABLE f;

	INJECT_INTERNAL_DATA(INJECTION_DATA* data, DWORD os_ver, DWORD os_build_ver);
};

DWORD CODE_SEG(".inj_int$1") __stdcall InjectInternal(INJECT_INTERNAL_DATA* data);
DWORD CODE_SEG(".inj_int$2") __stdcall InjectInternal_End();