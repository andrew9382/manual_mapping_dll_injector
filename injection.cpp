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

	if (!fs::exists(dll_path))
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

	if (flags & INJ_LOAD_DLL_COPY)
	{
		wchar_t* temp_dir = new wchar_t[MAX_PATH];
		
		if (!temp_dir)
		{
			return 0;
		}

		if (!GetTempPathW(MAX_PATH, temp_dir))
		{
			delete[] temp_dir;
			
			return 0;
		}

		std::wstring new_path = temp_dir;

		delete[] temp_dir;

		new_path += fs::path(data->dll_path).filename();

		try
		{
			if (!fs::copy_file(data->dll_path, new_path))
			{
				return 0;
			}
		}
		catch (fs::filesystem_error& err)
		{
			if (err.code().value() != 80)
			{
				return 0;
			}
		}
	
		wcscpy(data->dll_path, new_path.c_str());
	}
	
	if (flags & INJ_SCRAMBLE_DLL_NAME)
	{
		wchar_t* scrambled_name = new wchar_t[11];

		if (!scrambled_name)
		{
			return 0;
		}

		srand(time(NULL));

		for (DWORD i = 0; i < 10; ++i)
		{
			int rand_choose = _random(1, 3);

			switch (rand_choose)
			{
			case 1:
				scrambled_name[i] = wchar_t('a' + _random(0, 25));
				break;

			case 2:
				scrambled_name[i] = wchar_t('A' + _random(0, 25));
				break;

			case 3:
				scrambled_name[i] = wchar_t('0' + _random(0, 8));
				break;
			}
		}

		scrambled_name[10] = L'\0';

		fs::path scrambled_path(data->dll_path);

		scrambled_path.remove_filename();
		scrambled_path += scrambled_name;
		scrambled_path += L".dll";
		
		delete[] scrambled_name;

		fs::rename(data->dll_path, scrambled_path);

		wcscpy(data->dll_path, scrambled_path.c_str());
	}

	DWORD result = 0;

	std::vector<HOOK_SCAN_DATA> hk_vec;

	if (!HookScanAndPatch(&hk_vec, h_proc))
	{
		return 0;
	}

	if (data->mode == INJECTION_MODE::IM_MANUAL_MAPPING)
	{
		MANUAL_MAPPING_SHELL_DATA mm_data(data);

		size_t mm_size = (size_t)ManualMapShellEnd - (size_t)ManualMapShell;

		BYTE* mm_data_base = nullptr;
		BYTE* mm_shell_base = nullptr;

		mm_data_base = (BYTE*)VirtualAllocEx(h_proc, NULL, sizeof(MANUAL_MAPPING_SHELL_DATA), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
		if (!mm_data_base)
		{
			result = 0;
		
			goto MM_FAIL;
		}

		if (!WriteProcessMemory(h_proc, mm_data_base, &mm_data, sizeof(mm_data), NULL))
		{
			ERRLOG("Inject: WriteProcessMemory error: %d", GetLastError());
			
			result = 0;

			goto MM_FAIL;
		}

		mm_shell_base = (BYTE*)VirtualAllocEx(h_proc, NULL, mm_size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (!mm_shell_base)
		{
			result = 0;
			
			goto MM_FAIL;
		}

		if (!WriteProcessMemory(h_proc, mm_shell_base, ManualMapShell, mm_size, NULL))
		{
			result = 0;
		
			goto MM_FAIL;
		}

		result = StartRoutine(data->method, h_proc, (f_Routine)mm_shell_base, data->flags, mm_data_base, &data->out, START_ROUTINE_DEFAULT_TIMEOUT);
		
		if (result)
		{
			if (!ReadProcessMemory(h_proc, mm_data_base, &data->h_dll_out, sizeof(HMODULE), NULL))
			{
				result = 0;

				goto MM_FAIL;
			}
		}
		else
		{
			data->h_dll_out = 0;
		}

	MM_FAIL:

		if (mm_data_base)
		{
			VirtualFreeEx(h_proc, mm_data_base, NULL, MEM_RELEASE);
		}

		if (mm_shell_base)
		{
			VirtualFreeEx(h_proc, mm_shell_base, NULL, MEM_RELEASE);
		}
	}
	else // LoadLibraryExW
	{
		INJECT_INTERNAL_DATA llib_data(data, GetOSVersion(), GetOSBuildVersion());

		size_t llib_size = (size_t)InjectInternal_End - (size_t)InjectInternal;

		BYTE* llib_data_base = nullptr;
		BYTE* llib_shell_base = nullptr;

		llib_data_base = (BYTE*)VirtualAllocEx(h_proc, NULL, sizeof(INJECT_INTERNAL_DATA), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
		if (!llib_data_base)
		{
			result = 0;
	
			goto LLIB_FAIL;
		}

		if (!WriteProcessMemory(h_proc, llib_data_base, &llib_data, sizeof(INJECT_INTERNAL_DATA), NULL))
		{
			result = 0;
			
			goto LLIB_FAIL;
		}

		llib_shell_base = (BYTE*)VirtualAllocEx(h_proc, NULL, llib_size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (!llib_shell_base)
		{
			result = 0;
			
			goto LLIB_FAIL;
		}

		if (!WriteProcessMemory(h_proc, llib_shell_base, InjectInternal, llib_size, NULL))
		{
			result = 0;

			goto LLIB_FAIL;
		}

		result = StartRoutine(data->method, h_proc, (f_Routine)llib_shell_base, data->flags, llib_data_base, &data->out, START_ROUTINE_DEFAULT_TIMEOUT);

		if (result)
		{
			if (!ReadProcessMemory(h_proc, llib_data_base, &data->h_dll_out, sizeof(HMODULE), NULL))
			{
				result = 0;
			}
		}
		else
		{
			data->h_dll_out = 0;
		}

	LLIB_FAIL:

		if (llib_data_base)
		{
			VirtualFreeEx(h_proc, llib_data_base, NULL, MEM_RELEASE);
		}

		if (llib_shell_base)
		{
			VirtualFreeEx(h_proc, llib_shell_base, NULL, MEM_RELEASE);
		}
	}

	RestoreHookedFuncs(&hk_vec, h_proc, HOOK_RESTORE_MODE::HRM_RESTORE_HOOK);

	return result;
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
	this_module_inj_data.mode			= INJECTION_MODE::IM_LOAD_LIBRARY_EX_W;

	wcscpy(this_module_inj_data.dll_path, g_path_to_this_module.c_str());

	new_data.flags									= data->flags;
	new_data.method									= data->method;

	wcscpy(new_data.dll_path, data->dll_path);

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

		_ZeroMemory(new_data.data_buf, sizeof(new_data.data_buf));

		HANDLE h_proc = OpenProcess(proc_access, NULL, h.owner_pid);
		
		if (!h_proc)
		{
			fail_flag = true;

			goto HHIJACK_END;
		}

		if (is_target_elevated)
		{
			DWORD result = IsElevatedProcess(h_proc);
			if (result != -1 && result == 0)
			{
				fail_flag = true;

				goto HHIJACK_END;
			}
		}

		memcpy(this_module_inj_data.data_buf, &h.owner_pid, sizeof(h.owner_pid));

		if (!Inject(&this_module_inj_data))
		{
			fail_flag = true;

			goto HHIJACK_END;
		}

		if (!this_module_inj_data.h_dll_out)
		{
			fail_flag = true;

			goto HHIJACK_END;
		}
		
		remote_data = VirtualAllocEx(h_proc, NULL, sizeof(INJECTION_DATA), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
		if (!remote_data)
		{
			fail_flag = true;

			goto HHIJACK_END;
		}

		*(HANDLE*)new_data.data_buf = h.handle;

		if (!WriteProcessMemory(h_proc, remote_data, &new_data, sizeof(INJECTION_DATA), NULL))
		{
			fail_flag = true;

			goto HHIJACK_END;
		}

		remote_start = (f_Routine)((DWORD)&Start - (DWORD)g_h_current_module + (DWORD)this_module_inj_data.h_dll_out);

		result = StartRoutine(LAUNCH_METHOD::LM_NT_CREATE_THREAD_EX, h_proc, remote_start, (INJ_CTX_ALL ^ INJ_CTX_FAKE_START_ADDRESS) ^ INJ_CTX_HIDE_FROM_DEBUGGER, remote_data, &data->out, START_ROUTINE_DEFAULT_TIMEOUT * 5);
		if (!result)
		{
			fail_flag = true;

			goto HHIJACK_END;
		}

		if (!ReadProcessMemory(h_proc, (void*)(&g_executing_finished - (DWORD)g_h_current_module + (DWORD)this_module_inj_data.h_dll_out), &execute_finished_flag, sizeof(bool), NULL))
		{
			fail_flag = true;

			goto HHIJACK_END;
		}
		
	HHIJACK_END:

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