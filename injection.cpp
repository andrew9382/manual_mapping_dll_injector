#include "includes.hpp"

bool Inject(INJECTION_DATA* data)
{
	if (!data)
	{
		return false;
	}

	wchar_t* dll_path = data->dll_path;

	if (!dll_path)
	{
		return false;
	}

	if (!FileExists(dll_path))
	{
		return false;
	}

	bool by_proc_id = data->proc_id != 0;
	bool by_proc_name = wcslen(data->proc_name) != 0;
	bool by_h_proc = data->h_proc != 0;

	BYTE count = by_proc_id + by_h_proc + by_proc_name;

	if (count != 1)
	{
		return false;
	}

	DWORD proc_id = data->proc_id;

	if (by_proc_name)
	{
		proc_id = GetProcId(data->proc_name);

		if (!proc_id)
		{
			return false;
		}
	}

	ACCESS_MASK access_mask = PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION;
	if (data->mode == INJECTION_MODE::IM_LOAD_LIBRARY_EX_W && data->method != LAUNCH_METHOD::LM_THREAD_HIJACK)
	{
		access_mask |= PROCESS_CREATE_THREAD;
	}

	HANDLE h_proc = 0;

	// getting process handle
	if (data->flags & INJ_HANDLE_HIJACKING) // handle hijacking procedure
	{

	}
	else
	{
		if (by_proc_id || by_proc_name)
		{
			h_proc = OpenProcess(access_mask, NULL, proc_id);

			if (!h_proc)
			{
				return false;
			}
		}
		else // by process handle
		{
			PUBLIC_OBJECT_BASIC_INFORMATION h_info = { 0 };
			if (NT_FAIL(NATIVE::NtQueryObject(data->h_proc, OBJECT_INFORMATION_CLASS::ObjectBasicInformation, &h_info, sizeof(h_info), NULL)))
			{
				return false;
			}
			if ((h_info.GrantedAccess & access_mask) != access_mask)
			{
				return false;
			}

			h_proc = data->h_proc;
		}
	}

	DWORD info_flags = 0;
	if (!h_proc || !GetHandleInformation(h_proc, &info_flags))
	{
		return false;
	}

	bool is_native = IsNativeProcess(h_proc);
#ifdef _WIN64
	if (is_native)
	{
		if (!VerifyDLL(dll_path, IMAGE_FILE_MACHINE_AMD64))
		{
			return false;
		}
	}
	else
	{
		if (!VerifyDLL(dll_path, IMAGE_FILE_MACHINE_I386))
		{
			return false;
		}
	}
#else
	if (!VerifyDLL(dll_path, IMAGE_FILE_MACHINE_I386))
	{
		return false;
	}
#endif

	std::vector<HOOK_SCAN_DATA> hk_vec;

	if (data->mode == INJECTION_MODE::IM_MANUAL_MAPPING)
	{
		if (!HookScanAndPatch(&hk_vec, h_proc))
		{
			return false;
		}

		MANUAL_MAPPING_SHELL_DATA mm_data(data);

		size_t mm_size = (DWORD)ManualMapShellEnd - (DWORD)ManualMapShell;

		BYTE* mm_data_base = (BYTE*)VirtualAllocEx(h_proc, NULL, sizeof(MANUAL_MAPPING_SHELL_DATA), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
		if (!mm_data_base)
		{
			return false;
		}

		if (!WriteProcessMemory(h_proc, mm_data_base, &mm_data, sizeof(mm_data), NULL))
		{
			ERRLOG("Inject: WriteProcessMemory error: %d", GetLastError());

			VirtualFreeEx(h_proc, mm_data_base, NULL, MEM_RELEASE);

			return false;
		}

		BYTE* mm_shell_base = (BYTE*)VirtualAllocEx(h_proc, NULL, mm_size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (!mm_shell_base)
		{
			VirtualFreeEx(h_proc, mm_data_base, NULL, MEM_RELEASE);

			return false;
		}

		if (!WriteProcessMemory(h_proc, mm_shell_base, ManualMapShell, mm_size, NULL))
		{
			VirtualFreeEx(h_proc, mm_data_base, NULL, MEM_RELEASE);
			VirtualFreeEx(h_proc, mm_shell_base, NULL, MEM_RELEASE);

			return false;
		}

		DWORD result = StartRoutine(data->method, h_proc, (f_Routine)mm_shell_base, data->flags, mm_data_base, &data->out, 2000);
		
		VirtualFreeEx(h_proc, mm_data_base, NULL, MEM_RELEASE);
		VirtualFreeEx(h_proc, mm_shell_base, NULL, MEM_RELEASE);

		RestoreHookedFuncs(&hk_vec, h_proc, HOOK_RESTORE_MODE::HRM_RESTORE_HOOK);

		return result;
	}
	else // LoadLibraryExW
	{

	}

	return true;
}