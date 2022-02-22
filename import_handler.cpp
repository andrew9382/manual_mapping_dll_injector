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

template <typename T>
DWORD GetSymAddressNative(const wchar_t* sym_name, T& func, IMPORT_INDEX mode = IMPORT_INDEX::II_NTDLL)
{
	if (!sym_parser.IsReady())
	{
		return 0;
	}

	DWORD RVA = sym_parser.GetSymbolAddress(sym_name);
	if (!RVA)
	{
		return 0;
	}

	DWORD ret = 0;
	switch (mode)
	{
	case IMPORT_INDEX::II_NTDLL:
		ret = RVA + (DWORD)g_h_NTDLL;
		break;

	case IMPORT_INDEX::II_KERNEL32:
		ret = RVA + (DWORD)g_h_KERNEL32;
		break;
	}

	if (ret)
	{
		func = (T)ret;
	}

	return ret;
}

bool ResolveImports(SymbolLoader* loader)
{
	if (!loader)
	{
		return false;
	}

	if (!loader->IsReady())
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

	if (!sym_parser.Initialize(loader))
	{
		return false;
	}

	INIT_WIN32_FUNC(LoadLibraryA, g_h_KERNEL32);

	if (!NATIVE::p_LoadLibraryA)
	{
		return false;
	}

	if (!GetSymAddressNative(_FUNC_(NtQueryObject)))				return false;
	if (!GetSymAddressNative(_FUNC_(NtQuerySystemInformation)))		return false;

	if (!GetSymAddressNative(_FUNC_(LdrGetProcedureAddress)))		return false;

	if (!GetSymAddressNative(_FUNC_(LdrLoadDll)))					return false;
	if (!GetSymAddressNative(_FUNC_(LdrUnloadDll)))					return false;

	if (!GetSymAddressNative(_FUNC_(RtlFreeHeap)))					return false;
	if (!GetSymAddressNative(_FUNC_(LdrpHeap)))						return false;
	if (!GetSymAddressNative(_FUNC_(RtlAllocateHeap)))				return false;
	if (!GetSymAddressNative(_FUNC_(NtAllocateVirtualMemory)))		return false;
	if (!GetSymAddressNative(_FUNC_(NtFreeVirtualMemory)))			return false;

	if (!GetSymAddressNative(_FUNC_(memmove)))						return false;

	if (!GetSymAddressNative(_FUNC_(NtOpenFile)))					return false;
	if (!GetSymAddressNative(_FUNC_(NtClose)))						return false;
	if (!GetSymAddressNative(_FUNC_(NtSetInformationFile)))			return false;
	if (!GetSymAddressNative(_FUNC_(NtQueryInformationFile)))		return false;
	if (!GetSymAddressNative(_FUNC_(NtReadFile)))					return false;

	if (!GetSymAddressNative(_FUNC_(LdrLockLoaderLock)))			return false;
	if (!GetSymAddressNative(_FUNC_(LdrUnlockLoaderLock)))			return false;

	if (!GetSymAddressNative(_FUNC_(NtCreateThreadEx)))				return false;
	
	return true;
}