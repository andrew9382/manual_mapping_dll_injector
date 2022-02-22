#include "includes.hpp"

DWORD Inject(INJECTION_DATA* data)
{
	if (!data)
	{
		return 0;
	}

	wchar_t* dll_path = data->dll_path;

	if (!dll_path)
	{
		return 0;
	}

	if (!FileExists(dll_path))
	{
		return 0;
	}
	
	DWORD flags = data->flags;

	DWORD		target_id	= 0;
	HANDLE		h_proc		= 0;
	wchar_t*	proc_name	= nullptr;

	if (flags & INJ_BY_PROCESS_ID)
	{
		if (flags & (INJ_BY_HANDLE_HIJACK_AND_ID | INJ_BY_PROCESS_NAME | INJ_BY_HANDLE | INJ_BY_HANDLE_HIJACK_AND_NAME))
		{
			return 0;
		}

		target_id = *(DWORD*)data->data_buf;
	}
	else if (flags & INJ_BY_HANDLE_HIJACK_AND_ID)
	{
		if (flags & (INJ_BY_PROCESS_NAME | INJ_BY_PROCESS_ID | INJ_BY_HANDLE | INJ_BY_HANDLE_HIJACK_AND_NAME))
		{
			return 0;
		}
	
		target_id = *(DWORD*)data->data_buf;
	}
	else if (flags & INJ_BY_HANDLE_HIJACK_AND_NAME)
	{
		if (flags & (INJ_BY_PROCESS_NAME | INJ_BY_PROCESS_ID | INJ_BY_HANDLE | INJ_BY_HANDLE_HIJACK_AND_ID))
		{
			return 0;
		}

		proc_name = (wchar_t*)data->data_buf;
	}
	else if (flags & INJ_BY_PROCESS_NAME)
	{
		if (flags & (INJ_BY_PROCESS_ID | INJ_BY_HANDLE | INJ_BY_HANDLE_HIJACK_AND_ID | INJ_BY_HANDLE_HIJACK_AND_NAME))
		{
			return 0;
		}

		proc_name = (wchar_t*)data->data_buf;
	}
	else if (flags & INJ_BY_HANDLE)
	{
		if (flags & (INJ_BY_PROCESS_ID | INJ_BY_PROCESS_NAME | INJ_BY_HANDLE_HIJACK_AND_ID | INJ_BY_HANDLE_HIJACK_AND_NAME))
		{
			return 0;
		}

		h_proc = *(HANDLE*)data->data_buf;
	}
	else
	{
		return 0;
	}

	if (flags & (INJ_BY_PROCESS_NAME | INJ_BY_HANDLE_HIJACK_AND_NAME))
	{
		if (!proc_name)
		{
			return 0;
		}

		if (!wcslen(proc_name))
		{
			return 0;
		}

		target_id = GetProcId(proc_name);

		if (!target_id)
		{
			return 0;
		}
	}

	ACCESS_MASK access_mask = PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION;
	if (data->method == LAUNCH_METHOD::LM_NT_CREATE_THREAD_EX)
	{
		access_mask |= PROCESS_CREATE_THREAD;
	}

	if (flags & (INJ_BY_HANDLE_HIJACK_AND_NAME | INJ_BY_HANDLE_HIJACK_AND_ID)) // handle hijacking procedure
	{
		return HijackHandle(data, access_mask, target_id);
	}
	else if (flags & (INJ_BY_PROCESS_ID | INJ_BY_PROCESS_NAME))
	{
		h_proc = OpenProcess(access_mask, NULL, target_id);
	}

	DWORD info_flags = 0;
	if (!h_proc || !GetHandleInformation(h_proc, &info_flags))
	{
		return 0;
	}

	bool is_native = IsNativeProcess(h_proc);
#ifdef _WIN64
	if (is_native)
	{
		if (!VerifyDLL(dll_path, IMAGE_FILE_MACHINE_AMD64))
		{
			return 0;
		}
	}
	else
	{
		if (!VerifyDLL(dll_path, IMAGE_FILE_MACHINE_I386))
		{
			return 0;
		}
	}
#else
	if (!VerifyDLL(dll_path, IMAGE_FILE_MACHINE_I386))
	{
		return 0;
	}
#endif

	std::vector<HOOK_SCAN_DATA> hk_vec;

	if (data->mode == INJECTION_MODE::IM_MANUAL_MAPPING)
	{
		if (!HookScanAndPatch(&hk_vec, h_proc))
		{
			return 0;
		}

		MANUAL_MAPPING_SHELL_DATA mm_data(data);

		size_t mm_size = (DWORD)ManualMapShellEnd - (DWORD)ManualMapShell;

		BYTE* mm_data_base = (BYTE*)VirtualAllocEx(h_proc, NULL, sizeof(MANUAL_MAPPING_SHELL_DATA), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
		if (!mm_data_base)
		{
			return 0;
		}

		if (!WriteProcessMemory(h_proc, mm_data_base, &mm_data, sizeof(mm_data), NULL))
		{
			ERRLOG("Inject: WriteProcessMemory error: %d", GetLastError());

			VirtualFreeEx(h_proc, mm_data_base, NULL, MEM_RELEASE);

			return 0;
		}

		BYTE* mm_shell_base = (BYTE*)VirtualAllocEx(h_proc, NULL, mm_size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (!mm_shell_base)
		{
			VirtualFreeEx(h_proc, mm_data_base, NULL, MEM_RELEASE);

			return 0;
		}

		if (!WriteProcessMemory(h_proc, mm_shell_base, ManualMapShell, mm_size, NULL))
		{
			VirtualFreeEx(h_proc, mm_data_base, NULL, MEM_RELEASE);
			VirtualFreeEx(h_proc, mm_shell_base, NULL, MEM_RELEASE);

			return 0;
		}

		DWORD result = StartRoutine(data->method, h_proc, (f_Routine)mm_shell_base, data->flags, mm_data_base, &data->out, START_ROUTINE_DEFAULT_TIMEOUT);
		
		if (result)
		{
			ReadProcessMemory(h_proc, mm_data_base, &data->h_dll_out, sizeof(HMODULE), NULL);
		}
		else
		{
			data->h_dll_out = 0;
		}

		VirtualFreeEx(h_proc, mm_data_base, NULL, MEM_RELEASE);
		VirtualFreeEx(h_proc, mm_shell_base, NULL, MEM_RELEASE);

		RestoreHookedFuncs(&hk_vec, h_proc, HOOK_RESTORE_MODE::HRM_RESTORE_HOOK);

		return result;
	}
	else // LoadLibraryExW
	{

	}

	return 1;
}

DWORD HijackHandle(INJECTION_DATA* data, ACCESS_MASK desired_access, DWORD target_pid)
{
	std::vector<SYSTEM_HANDLE_TABLE_ENTRY_INFO> sys_proc_handles;

	if (!EnumProcessHandles(&sys_proc_handles))
	{
		return 0;
	}

	std::vector<HANDLE_INFO> handles_to_target_process;

	if (!FindProcessHandles(&sys_proc_handles, target_pid, &handles_to_target_process, desired_access))
	{
		return 0;
	}

	if (handles_to_target_process.empty())
	{
		return 0;
	}

	bool is_target_elevated = false;

	{
		HANDLE h_hijack_proc = OpenProcess(PROCESS_DUP_HANDLE, NULL, handles_to_target_process[0].owner_pid);
		if (!h_hijack_proc)
		{
			return 0;
		}

		HANDLE h_dup = nullptr;
		if (!DuplicateHandle(h_hijack_proc, handles_to_target_process[0].handle, GetCurrentProcess(), &h_dup, PROCESS_QUERY_INFORMATION, NULL, NULL))
		{
			return 0;
		}

		DWORD result = IsElevatedProcess(h_dup);
		if (result == -1)
		{
			CloseHandle(h_dup);

			return 0;
		}

		CloseHandle(h_dup);

		is_target_elevated = result != 0;
	}

	ACCESS_MASK proc_access = PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION;

	INJECTION_DATA this_module_inj_data;
	INJECTION_DATA new_data;

	this_module_inj_data.method			= LAUNCH_METHOD::LM_NT_CREATE_THREAD_EX;
	this_module_inj_data.flags			= (INJ_CTX_ALL ^ INJ_CTX_FAKE_START_ADDRESS) | INJ_BY_PROCESS_ID;
	this_module_inj_data.mode			= INJECTION_MODE::IM_MANUAL_MAPPING;

	wcscpy(this_module_inj_data.dll_path, g_path_to_this_module);

	new_data.flags									= data->flags;
	new_data.method									= data->method;
	new_data.this_module_manual_mapped_flag			= true;

	wcscpy(new_data.dll_path, data->dll_path);
	wcscpy(new_data.start_args.full_own_module_path, g_path_to_this_module);
	wcscpy(new_data.start_args.own_module_folder_path, g_path_to_this_module_folder);

	if (new_data.flags & INJ_BY_HANDLE_HIJACK_AND_ID)
	{
		new_data.flags ^= INJ_BY_HANDLE_HIJACK_AND_ID;
	}
	else
	{
		new_data.flags ^= INJ_BY_HANDLE_HIJACK_AND_NAME;
	}

	new_data.flags |= INJ_BY_HANDLE;

	for (auto& h : handles_to_target_process)
	{
		bool			fail_flag				= false;
		void*			remote_data				= nullptr;
		DWORD			result					= 0;
		f_Routine		remote_start			= nullptr;
		bool			execute_finished_flag	= false;

		ZeroMem(&new_data.data_buf);

		HANDLE h_proc = OpenProcess(proc_access, NULL, h.owner_pid);
		
		if (!h_proc)
		{
			fail_flag = true;

			goto END;
		}

		if (is_target_elevated)
		{
			DWORD result = IsElevatedProcess(h_proc);
			if (result != -1 && result == 0)
			{
				fail_flag = true;

				goto END;
			}
		}

		memcpy(this_module_inj_data.data_buf, &h.owner_pid, sizeof(h.owner_pid));

		if (!Inject(&this_module_inj_data))
		{
			fail_flag = true;

			goto END;
		}

		if (!this_module_inj_data.h_dll_out)
		{
			fail_flag = true;

			goto END;
		}
		
		remote_data = VirtualAllocEx(h_proc, NULL, sizeof(INJECTION_DATA), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
		if (!remote_data)
		{
			fail_flag = true;

			goto END;
		}

		*(HANDLE*)new_data.data_buf = h.handle;

		if (!WriteProcessMemory(h_proc, remote_data, &new_data, sizeof(INJECTION_DATA), NULL))
		{
			fail_flag = true;

			goto END;
		}

		remote_start = (f_Routine)((DWORD)&Start - (DWORD)g_h_current_module + (DWORD)this_module_inj_data.h_dll_out);

		result = StartRoutine(LAUNCH_METHOD::LM_NT_CREATE_THREAD_EX, h_proc, remote_start, (INJ_CTX_ALL ^ INJ_CTX_FAKE_START_ADDRESS) ^ INJ_CTX_HIDE_FROM_DEBUGGER, remote_data, &data->out, START_ROUTINE_DEFAULT_TIMEOUT * 5);
		if (!result)
		{
			fail_flag = true;

			goto END;
		}

		if (!ReadProcessMemory(h_proc, (void*)(&g_executing_finished - (DWORD)g_h_current_module + (DWORD)this_module_inj_data.h_dll_out), &execute_finished_flag, sizeof(bool), NULL))
		{
			// TODO: eject manually mapped module from process and cleanup
			
			fail_flag = true;

			goto END;
		}
		
END:

		if (remote_data)
		{
			VirtualFreeEx(h_proc, remote_data, NULL, MEM_RELEASE);

			remote_data = nullptr;
		}

		if (h_proc)
		{
			CloseHandle(h_proc);
		
			h_proc = 0;
		}

		if (fail_flag)
		{
			continue;
		}

		return result;
	}

	return 0;
}