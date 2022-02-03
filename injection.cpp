#include "includes.hpp"

//bool ManualMap(HANDLE h_proc, const wchar_t* dll_name)
//{
//	BYTE*					target_base		= nullptr;
//	BYTE*					src_data		= nullptr;
//	IMAGE_DOS_HEADER*		old_dos_header	= nullptr;
//	IMAGE_NT_HEADERS*		old_pe_header	= nullptr;
//	IMAGE_OPTIONAL_HEADER*	old_opt_header	= nullptr;
//	IMAGE_FILE_HEADER*		old_file_header	= nullptr;
//
//	if (!GetFileAttributesW(dll_name))
//	{
//		printf("[ERROR] file doesn`t exist!\n");
//
//		return false;
//	}
//
//	std::fstream file(dll_name, std::ios::in | std::ios::ate | std::ios::binary);
//	if (file.fail())
//	{
//		printf("[ERROR] opening file failed: %X\n", (DWORD)file.rdstate());
//		file.close();
//
//		return false;
//	}
//
//	DWORD file_size = (DWORD)file.tellg();
//	if (file_size < PAGE_SIZE)
//	{
//		printf("[ERROR] file size invalid!\n");
//		file.close();
//
//		return false;
//	}
//
//	src_data = new BYTE[file_size];
//	if (!src_data)
//	{
//		printf("[ERROR] memory allocation failed!\n");
//		file.close();
//
//		return false;
//	}
//
//	file.seekg(NULL, std::ios::beg);
//	file.read((char*)src_data, file_size);
//	file.close();
//
//	old_dos_header = (IMAGE_DOS_HEADER*)src_data;
//	if (old_dos_header->e_magic != IMAGE_DOS_SIGNATURE)
//	{
//		printf("[ERROR] invalid IMAGE_DOS_SIGNATURE\n");
//		delete[file_size] src_data;
//
//		return false;
//	}
//
//	old_pe_header = (IMAGE_NT_HEADERS*)(src_data + old_dos_header->e_lfanew);
//	if (old_pe_header->Signature != IMAGE_NT_SIGNATURE)
//	{
//		printf("[ERROR] invalid IMAGE_NT_SIGNATURE\n");
//		delete[file_size] src_data;
//
//		return false;
//	}
//
//	old_opt_header = (IMAGE_OPTIONAL_HEADER*)&old_pe_header->OptionalHeader;
//	old_file_header = (IMAGE_FILE_HEADER*)&old_pe_header->FileHeader;
//
//#ifdef _WIN64
//	if (old_file_header->Machine != IMAGE_FILE_MACHINE_AMD64)
//	{
//		printf("[ERROR] invalid platform\n");
//		delete[file_size] src_data;
//
//		return false;
//	}
//#else
//	if (old_file_header->Machine != IMAGE_FILE_MACHINE_I386)
//	{
//		printf("[ERROR] invalid platform\n");
//		delete[file_size] src_data;
//
//		return false;
//	}
//#endif
//
//	target_base = (BYTE*)VirtualAllocEx(h_proc, (LPVOID)old_opt_header->ImageBase, old_opt_header->SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
//	if (!target_base)
//	{
//		target_base = (BYTE*)VirtualAllocEx(h_proc, NULL, old_opt_header->SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
//		if (!target_base)
//		{
//			printf("[ERROR] VirtualAllocEx: %d\n", GetLastError());
//			delete[file_size] src_data;
//
//			return false;
//		}
//	}
//
//	BYTE* shellcode_stub_addr = (BYTE*)VirtualAllocEx(h_proc, NULL, PAGE_SIZE, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
//	if (!shellcode_stub_addr)
//	{
//		printf("[ERROR] VirtualAllocEx: %d\n", GetLastError());
//		delete[file_size] src_data;
//
//		return false;
//	}
//
//	memcpy(&shellcode_stub[1], &target_base, sizeof(target_base));
//
//	IMAGE_SECTION_HEADER* section_header = IMAGE_FIRST_SECTION(old_pe_header);
//
//	for (DWORD i = 0; i < old_file_header->NumberOfSections; ++i, ++section_header)
//	{
//		if (section_header->SizeOfRawData)
//		{
//			if (!WriteProcessMemory(h_proc, target_base + section_header->VirtualAddress, src_data + section_header->PointerToRawData, section_header->SizeOfRawData, NULL))
//			{
//				printf("[ERROR] sections mapping: %d\n", GetLastError());
//				delete[file_size] src_data;
//				VirtualFreeEx(h_proc, shellcode_stub_addr, NULL, MEM_RELEASE);
//				VirtualFreeEx(h_proc, target_base, NULL, MEM_RELEASE);
//				return false;
//			}
//		}
//	}
//
//	void* shellcode_func = VirtualAllocEx(h_proc, NULL, PAGE_SIZE, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
//	if (!shellcode_func)
//	{
//		printf("[ERROR] VirtualAllocEx: %d\n", GetLastError());
//		VirtualFreeEx(h_proc, shellcode_stub_addr, NULL, MEM_RELEASE);
//		VirtualFreeEx(h_proc, target_base, NULL, MEM_RELEASE);
//		delete[file_size] src_data;
//
//		return false;
//	}
//
//	DWORD jmp_dst = JMP_DST(shellcode_func, shellcode_stub_addr + 5);
//	memcpy(&shellcode_stub[6], &jmp_dst, sizeof(jmp_dst));
//	WriteProcessMemory(h_proc, shellcode_func, ShellcodeFunc, PAGE_SIZE, NULL);
//
//	//THREAD_HIJACK_CONTEXT hijack_cnt = { 0 };
//	//hijack_cnt.IP_new_value = (DWORD)shellcode_stub_addr;
//	//hijack_cnt.proc_id = GetProcessId(h_proc);
//
//	//if (!HijackThread(&hijack_cnt))
//	//{
//	//	printf("[ERROR] HijackThread failed\n");
//	//	VirtualFreeEx(h_proc, shellcode_func, NULL, MEM_RELEASE);
//	//	VirtualFreeEx(h_proc, shellcode_stub_addr, NULL, MEM_RELEASE);
//	//	VirtualFreeEx(h_proc, target_base, NULL, MEM_RELEASE);
//	//	delete[file_size] src_data;
//
//	//	return false;
//	//}
//	
//	MANUAL_MAPPING_DATA map_data = { 0 };
//	map_data.p_LoadLibraryA = LoadLibraryA;
//	map_data.p_GetProcAddress = (f_GetProcAddress)GetProcAddress;
//
//	memcpy(src_data, &map_data, sizeof(map_data));
//	WriteProcessMemory(h_proc, target_base, src_data, PAGE_SIZE, NULL);
//	delete[file_size] src_data;
//	
//	jmp_dst = JMP_DST(hijack_cnt.IP_old_value, shellcode_stub_addr + 10);
//	memcpy(&shellcode_stub[11], &jmp_dst, sizeof(jmp_dst));
//	WriteProcessMemory(h_proc, shellcode_stub_addr, &shellcode_stub[0], shellcode_stub.size(), NULL);
//
//	ResumeThread(hijack_cnt.h_thread);
//	CloseHandle(hijack_cnt.h_thread);
//
//	//HANDLE h_thread = CreateRemoteThread(h_proc, NULL, NULL, (LPTHREAD_START_ROUTINE)shellcode_func, target_base, NULL, NULL);
//	//if (h_thread == INVALID_HANDLE_VALUE)
//	//{
//	//	printf("CreateRemoteThread error: %d", GetLastError());
//	//	VirtualFreeEx(h_proc, shellcode_addr, NULL, MEM_RELEASE);
//	//	VirtualFreeEx(h_proc, shellcode_func, NULL, MEM_RELEASE);
//	//	VirtualFreeEx(h_proc, target_base, NULL, MEM_RELEASE);
//	// 
//	//	return false;
//	//}
//
//	HINSTANCE check_data = NULL;
//	while (!check_data)
//	{
//		ReadProcessMemory(h_proc, target_base, &check_data, sizeof(HINSTANCE), NULL);
//		Sleep(100);
//	}
//
//	VirtualFreeEx(h_proc, shellcode_func, NULL, MEM_RELEASE);
//	VirtualFreeEx(h_proc, shellcode_stub_addr, NULL, MEM_RELEASE);
//
//	//CloseHandle(h_thread);
//	CloseHandle(h_proc);
//	
//	return true;
//}

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
	if (data->mode == INJECTION_MODE::IM_LOAD_LIBRARY_EX_W)
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

	if (data->mode == INJECTION_MODE::IM_MANUAL_MAPPING)
	{
		MANUAL_MAPPING_SHELL_DATA mm_data(data);

		size_t mm_size = (DWORD)ManualMapShellEnd - (DWORD)ManualMapShell;

		BYTE* mm_shell_base = (BYTE*)VirtualAllocEx(data->h_proc, NULL, mm_size + sizeof(MANUAL_MAPPING_SHELL_DATA), MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (!mm_shell_base)
		{
			return false;
		}

		if (!WriteProcessMemory(data->h_proc, mm_shell_base, &mm_data, sizeof(mm_data), NULL))
		{
			VirtualFreeEx(data->h_proc, mm_shell_base, NULL, MEM_RELEASE);

			return false;
		}

		if (!WriteProcessMemory(data->h_proc, mm_shell_base + sizeof(mm_data), ManualMapShell, mm_size, NULL))
		{
			VirtualFreeEx(data->h_proc, mm_shell_base, NULL, MEM_RELEASE);

			return false;
		}

		DWORD result = StartRoutine(data->method, data->h_proc, (f_Routine)(mm_shell_base + sizeof(mm_data)), mm_shell_base, &data->out, 300);
		
		VirtualFreeEx(data->h_proc, mm_shell_base, NULL, MEM_RELEASE);

		return result;
	}
	else // LoadLibraryEx
	{

	}

	return true;
}