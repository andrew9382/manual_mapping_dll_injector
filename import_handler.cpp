#include "includes.hpp"

DWORD GetOSVersion()
{
	if (g_os_build_number)
	{
		return g_os_build_number;
	}

#ifdef _WIN64
	PEB* peb = (PEB*)__readgsqword(0x60);
#else
	PEB* peb = (PEB*)__readfsdword(0x30);
#endif

	if (!peb)
	{
		return 0;
	}

	DWORD v_hi = peb->OSMajorVersion;
	DWORD v_lo = peb->OSMinorVersion;

	for (; v_lo >= 10; v_lo /= 10);

	g_os_version = v_hi * 10 + v_lo;
	g_os_build_number = peb->OSBuildNumber;

	return g_os_version;
}

DWORD GetOSBuildVersion()
{
	return g_os_build_number;
}

bool IsWin7OrGreater()
{
	return (GetOSVersion() >= g_Win7);
}

bool IsWin8OrGreater()
{
	return (GetOSVersion() >= g_Win8);
}

bool IsWin81OrGreater()
{
	return (GetOSVersion() >= g_Win81);
}

bool IsWin10OrGreater()
{
	return (GetOSVersion() >= g_Win10);

}

bool IsWin11OrGreater()
{
	return (GetOSVersion() >= g_Win11 && GetOSBuildVersion() >= g_Win11_21H2);
}

bool ResolveImports(SymbolLoader* loader)
{
	if (!loader)
	{
		return false;
	}

	if (!g_h_NTDLL)
	{
		g_h_NTDLL = LoadLibraryW(L"ntdll.dll");

		if (!g_h_NTDLL)
		{
			return false;
		}
	}
	
	if (!g_h_KERNEL32)
	{
		g_h_KERNEL32 = LoadLibraryW(L"kernel32.dll");

		if (!g_h_KERNEL32)
		{
			return false;
		}
	}

	SymbolParser sym_parser;

	if (!sym_parser.Initialize(loader))
	{
		return false;
	}

	if (	!(GET_ADDR_NT_NATIVE(sym_parser, NtQueryObject)))				return false;

	if (	!(GET_ADDR_NT_NATIVE(sym_parser, LdrGetProcedureAddress)))		return false;

	if (	!(GET_ADDR_NT_NATIVE(sym_parser, LdrLoadDll)))					return false;

	if (	!(GET_ADDR_NT_NATIVE(sym_parser, RtlFreeHeap)))					return false;
	if (	!(GET_ADDR_NT_NATIVE(sym_parser, LdrpHeap)))					return false;
	if (	!(GET_ADDR_NT_NATIVE(sym_parser, RtlAllocateHeap)))				return false;
	if (	!(GET_ADDR_NT_NATIVE(sym_parser, NtAllocateVirtualMemory)))		return false;
	if (	!(GET_ADDR_NT_NATIVE(sym_parser, NtFreeVirtualMemory)))			return false;

	if (	!(GET_ADDR_NT_NATIVE(sym_parser, memmove)))						return false;

	if (	!(GET_ADDR_NT_NATIVE(sym_parser, NtOpenFile)))					return false;
	if (	!(GET_ADDR_NT_NATIVE(sym_parser, NtClose)))						return false;
	if (	!(GET_ADDR_NT_NATIVE(sym_parser, NtSetInformationFile)))		return false;
	if (	!(GET_ADDR_NT_NATIVE(sym_parser, NtQueryInformationFile)))		return false;
	if (	!(GET_ADDR_NT_NATIVE(sym_parser, NtReadFile)))					return false;

	if (	!(GET_ADDR_NT_NATIVE(sym_parser, LdrLockLoaderLock)))			return false;
	if (	!(GET_ADDR_NT_NATIVE(sym_parser, LdrUnlockLoaderLock)))			return false;
	
	return true;
}

DWORD GetSymAddressNative(SymbolParser* sym_parser, const wchar_t* sym_name, IMPORT_INDEX mode = IMPORT_INDEX::II_NTDLL)
{
	if (!sym_parser)
	{
		return 0;
	}

	if (!sym_parser->IsReady())
	{
		return 0;
	}

	DWORD RVA = sym_parser->GetSymbolAddress(sym_name);
	if (!RVA)
	{
		return 0;
	}

	switch (mode)
	{
	case IMPORT_INDEX::II_NTDLL:
		return RVA + (DWORD)g_h_NTDLL;

	case IMPORT_INDEX::II_KERNEL32:
		return RVA + (DWORD)g_h_KERNEL32;
	}

	return 0;
}