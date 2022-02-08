#include "includes.hpp"

bool HookScanAndPatch(std::vector<HOOK_SCAN_DATA>* hk_vec, HANDLE h_proc)
{
	if (!hk_vec || !h_proc)
	{
		return false;
	}

	if (!hk_vec->empty())
	{
		hk_vec->clear();
	}

	ProcessInfo PI;

	if (!PI.SetProcess(h_proc))
	{
		return false;
	}

	DWORD modules_count	 = sizeof(modules) / sizeof(modules[0]);
	DWORD funcs_count	 = sizeof(to_hk_scan) / sizeof(to_hk_scan[0]);

	for (DWORD i = 0; i < modules_count; ++i)
	{
		HMODULE mod			= GetModuleHandleW(modules[i]);
		HMODULE remote_mod  = PI._GetModuleHandle(modules[i]);
		
		if (!mod || !remote_mod)
		{
			if (!hk_vec->empty())
			{
				hk_vec->clear();
			}
		
			return false;
		}
		
		for (DWORD j = 0; j < funcs_count; ++j)
		{
			DWORD func_addr = (DWORD)GetProcAddress(mod, to_hk_scan[j]);
			
			if (func_addr)
			{
				HOOK_SCAN_DATA data;

				data.func_addr = (void*)(func_addr - (DWORD)mod + (DWORD)remote_mod);
				data.func_name = to_hk_scan[j];
				
				memcpy(data.orig_bytes, (void*)func_addr, SCAN_BYTES_COUNT);

				if (!ReadProcessMemory(h_proc, data.func_addr, data.remote_bytes, SCAN_BYTES_COUNT, NULL))
				{
					if (!hk_vec->empty())
					{
						hk_vec->clear();
					}

					return false;
				}

				hk_vec->push_back(data);
			}
		}
	}

	if (hk_vec->empty())
	{
		return false;
	}

	if (hk_vec->size() != funcs_count)
	{
		hk_vec->clear();

		return false;
	}

	CompareFuncs(hk_vec);

	if (!RestoreHookedFuncs(hk_vec, h_proc, HOOK_RESTORE_MODE::HRM_RESTORE_ORIG))
	{
		hk_vec->clear();

		return false;
	}

	return true;
}

bool CompareFuncs(std::vector<HOOK_SCAN_DATA>* hk_vec)
{
	if (!hk_vec || hk_vec->empty())
	{
		return false;
	}

	for (auto& el : *hk_vec)
	{
		el.hooked = false;

		for (DWORD i = 0; i < SCAN_BYTES_COUNT; ++i)
		{
			if (el.orig_bytes[i] != el.remote_bytes[i])
			{
				el.hooked = true;
			
				break;
			}
		}
	}

	return true;
}

bool RestoreHookedFuncs(std::vector<HOOK_SCAN_DATA>* hk_vec, HANDLE h_proc, HOOK_RESTORE_MODE mode)
{
	if (!hk_vec || hk_vec->empty() || !h_proc)
	{
		return false;
	}

	for (auto& el : *hk_vec)
	{
		if (el.hooked)
		{
			if (mode == HOOK_RESTORE_MODE::HRM_RESTORE_ORIG)
			{
				if (!WriteProcessMemory(h_proc, el.func_addr, el.orig_bytes, SCAN_BYTES_COUNT, NULL))
				{
					return false;
				}
			}
			else
			{
				if (!WriteProcessMemory(h_proc, el.func_addr, el.remote_bytes, SCAN_BYTES_COUNT, NULL))
				{
					return false;
				}
			}
		}
	}

	return true;
}