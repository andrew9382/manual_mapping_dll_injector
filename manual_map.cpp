#include "includes.hpp"

__forceinline int _wcslen(const wchar_t* str)
{
	if (!str)
	{
		return -1;
	}

	int i = 0;

	for (; *str != L'\0'; ++str, ++i);

	return i * sizeof(wchar_t);
}

__forceinline int _strlen(const char* str)
{
	if (!str)
	{
		return -1;
	}
	
	int i = 0;

	for (; *str; ++str, ++i);
	
	return i * sizeof(char);
}

template <typename T>
__forceinline T* _HeapAlloc(MANUAL_MAP_FUNCTION_TABLE* f, size_t size)
{
	return (T*)f->RtlAllocateHeap(f->p_LdrpHeap, HEAP_ZERO_MEMORY, size * sizeof(T));
}


__forceinline bool _FreeHeap(MANUAL_MAP_FUNCTION_TABLE* f, void* addr)
{
	return (bool)f->RtlFreeHeap(f->p_LdrpHeap, NULL, addr);
}

__forceinline void AddDependency(MANUAL_MAP_FUNCTION_TABLE* f, MM_DEPENDENCY_RECORD** rec, HMODULE new_handle)
{
	if (!rec)
	{
		return;
	}

	if (!(*rec))
	{
		*rec = _HeapAlloc<MM_DEPENDENCY_RECORD>(f, 1);

		(*rec)->f_link = nullptr;
		(*rec)->h_dll = new_handle;

		return;
	}

	MM_DEPENDENCY_RECORD* cur = *rec;
	while (cur->f_link != nullptr)
	{
		cur = cur->f_link;
	}

	cur->f_link = _HeapAlloc<MM_DEPENDENCY_RECORD>(f, 1);
	cur->f_link->h_dll = new_handle;
	cur->f_link->f_link = nullptr;
}

__forceinline void DeleteAllDependencies(MANUAL_MAP_FUNCTION_TABLE* f, MM_DEPENDENCY_RECORD* rec)
{
	if (!rec)
	{
		return;
	}

	MM_DEPENDENCY_RECORD* tmp = nullptr;
	while (rec)
	{
		f->p_FreeLibrary(rec->h_dll);
		tmp = rec->f_link;
		_FreeHeap(f, rec);
		rec = tmp;
	}
}

DWORD CODE_SEG(".mmap_seg$1") __stdcall ManualMapShell(MANUAL_MAPPING_SHELL_DATA* mp_data)
{
	if (!mp_data)
	{
		return 0;
	}

	MANUAL_MAP_FUNCTION_TABLE* f = &mp_data->f_table;

	IMAGE_DOS_HEADER*		dos_header	 = nullptr;
	IMAGE_NT_HEADERS*		pe_header	 = nullptr;
	IMAGE_FILE_HEADER*		file_header	 = nullptr;
	IMAGE_OPTIONAL_HEADER*	opt_header	 = nullptr;
	f_DLL_ENTRY_POINT		DllMain		 = nullptr;

	HANDLE h_proc = NtCurrentProcess();

	if (!f)
	{
		return 0;
	}

	f->p_LdrpHeap = *f->LdrpHeap;
	if (!f->p_LdrpHeap)
	{
		return 0;
	}

	MM_DEPENDENCY_RECORD* imports = nullptr;

	UNICODE_STRING* u_str = _HeapAlloc<UNICODE_STRING>(f, 1);
	
	if (!u_str)
	{
		return 0;
	}

	u_str->Length = _wcslen(mp_data->dll_path);
	u_str->MaxLength = sizeof(wchar_t[MAX_PATH + 4]);
	u_str->szBuffer = mp_data->dll_path;

	OBJECT_ATTRIBUTES* obj_attr = _HeapAlloc<OBJECT_ATTRIBUTES>(f, 1);
	
	if (!obj_attr)
	{
		_FreeHeap(f, u_str);

		return 0;
	}

	obj_attr->Length = sizeof(OBJECT_ATTRIBUTES);
	obj_attr->ObjectName = u_str;
	obj_attr->Attributes = OBJ_CASE_INSENSITIVE;

	IO_STATUS_BLOCK* io_status = _HeapAlloc<IO_STATUS_BLOCK>(f, 1);

	if (!io_status)
	{
		_FreeHeap(f, u_str);
		_FreeHeap(f, obj_attr);

		return 0;
	}

	HANDLE h_file = 0;
	if (NT_FAIL(f->NtOpenFile(&h_file, FILE_GENERIC_READ, obj_attr, io_status, FILE_SHARE_READ, FILE_SYNCHRONOUS_IO_NONALERT)))
	{
		_FreeHeap(f, obj_attr);
		_FreeHeap(f, io_status);

		return 0;
	}

	_FreeHeap(f, u_str);
	_FreeHeap(f, obj_attr);

	FILE_STANDARD_INFO* fsi = _HeapAlloc<FILE_STANDARD_INFO>(f, 1);
	if (!fsi)
	{
		f->NtClose(h_file);

		_FreeHeap(f, io_status);

		return 0;
	}

	if (NT_FAIL(f->NtQueryInformationFile(h_file, io_status, fsi, sizeof(FILE_STANDARD_INFO), FILE_INFORMATION_CLASS::FileStandardInformation)))
	{
		f->NtClose(h_file);

		_FreeHeap(f, io_status);
		_FreeHeap(f, fsi);

		return 0;
	}

	DWORD file_size = fsi->AllocationSize.LowPart;

	_FreeHeap(f, fsi);

	FILE_POSITION_INFORMATION* f_pos = _HeapAlloc<FILE_POSITION_INFORMATION>(f, 1);
	if (!f_pos)
	{
		f->NtClose(h_file);

		_FreeHeap(f, io_status);

		return 0;
	}

	if (NT_FAIL(f->NtSetInformationFile(h_file, io_status, f_pos, sizeof(FILE_POSITION_INFORMATION), FILE_INFORMATION_CLASS::FilePositionInformation)))
	{
		f->NtClose(h_file);

		_FreeHeap(f, io_status);
		_FreeHeap(f, f_pos);

		return 0;
	}

	_FreeHeap(f, f_pos);

	BYTE* dll_raw = nullptr;
	if (NT_FAIL(f->NtAllocateVirtualMemory(h_proc, (void**)&dll_raw, NULL, &file_size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE)) || !dll_raw)
	{
		f->NtClose(h_file);

		_FreeHeap(f, io_status);

		return 0;
	}

	if (NT_FAIL(f->NtReadFile(h_file, NULL, NULL, NULL, io_status, dll_raw, file_size, NULL, NULL)))
	{
		f->NtClose(h_file);

		file_size = 0;
		f->NtFreeVirtualMemory(h_proc, (void**)&dll_raw, &file_size, MEM_RELEASE);

		_FreeHeap(f, io_status);

		return 0;
	}

	f->NtClose(h_file);

	_FreeHeap(f, io_status);

	dos_header   = (IMAGE_DOS_HEADER*)dll_raw;
	pe_header    = (IMAGE_NT_HEADERS*)(dll_raw + dos_header->e_lfanew);
	file_header  = &pe_header->FileHeader;
	opt_header   = &pe_header->OptionalHeader;

	BYTE*   image_base      = (BYTE*)opt_header->ImageBase;
	DWORD   image_size      = opt_header->SizeOfImage;
	size_t  sections_count  = file_header->NumberOfSections;

	if (NT_FAIL(f->NtAllocateVirtualMemory(h_proc, (void**)&image_base, NULL, &image_size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE)))
	{
		image_base = nullptr;
		if (NT_FAIL(f->NtAllocateVirtualMemory(h_proc, (void**)&image_base, NULL, &image_size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE)) || !image_base)
		{
			file_size = 0;
			f->NtFreeVirtualMemory(h_proc, (void**)&dll_raw, &file_size, MEM_RELEASE);

			return 0;
		}
	}

	// sections mapping
	IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(pe_header);
	for (DWORD i = 0; i < sections_count; ++i, ++sec)
	{
		if (sec->SizeOfRawData)
		{
			f->memmove(image_base + sec->VirtualAddress, dll_raw + sec->PointerToRawData, sec->SizeOfRawData);
		}
	}

	f->memmove(image_base, dll_raw, PAGE_SIZE); // move headers

	file_size = 0;
	f->NtFreeVirtualMemory(h_proc, (void**)&dll_raw, &file_size, MEM_RELEASE);

	dos_header	 = (IMAGE_DOS_HEADER*)image_base;
	pe_header    = (IMAGE_NT_HEADERS*)(image_base + dos_header->e_lfanew);
	file_header  = &pe_header->FileHeader;
	opt_header	 = &pe_header->OptionalHeader;

	DllMain = (f_DLL_ENTRY_POINT)(image_base + opt_header->AddressOfEntryPoint);

	DWORD location_delta = (DWORD)image_base - opt_header->ImageBase;
	if (location_delta)
	{
		if (!opt_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size)
		{
			image_size = 0;
			f->NtFreeVirtualMemory(h_proc, (void**)&image_base, &image_size, MEM_RELEASE);
			
			return 0;
		}

		IMAGE_BASE_RELOCATION* reloc_data = (IMAGE_BASE_RELOCATION*)(image_base + opt_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
		while (reloc_data->VirtualAddress)
		{
			DWORD amount_of_entries  = (reloc_data->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
			WORD* relative_info		 = (WORD*)(reloc_data + 1);

			for (DWORD i = 0; i < amount_of_entries; ++i, ++relative_info)
			{
				if (RELOC_FLAG(*relative_info))
				{
					DWORD* patch = (DWORD*)(image_base + reloc_data->VirtualAddress + (*relative_info & 0xFFF));
					*patch += (DWORD)location_delta;
				}
			}

			reloc_data = (IMAGE_BASE_RELOCATION*)((BYTE*)reloc_data + reloc_data->SizeOfBlock);
		}

		opt_header->ImageBase += location_delta;
	}

	if (opt_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size)
	{
		IMAGE_IMPORT_DESCRIPTOR* import_descriptor = (IMAGE_IMPORT_DESCRIPTOR*)(opt_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress + image_base);

		bool err_break = false;

		while (import_descriptor->Name)
		{
			char* dll_name = (char*)(image_base + import_descriptor->Name);
			HMODULE h_dll = f->p_LoadLibraryA(dll_name);

			if (!h_dll)
			{
				err_break = true;
				goto ERR_BREAK;
			}

			AddDependency(f, &imports, h_dll);

			IMAGE_THUNK_DATA* thunk_ref  = (IMAGE_THUNK_DATA*)(image_base + import_descriptor->OriginalFirstThunk);
			IMAGE_THUNK_DATA* func_ref   = (IMAGE_THUNK_DATA*)(image_base + import_descriptor->FirstThunk);

			if (!thunk_ref)
			{
				thunk_ref = func_ref;
			}

			for (; thunk_ref->u1.AddressOfData; ++thunk_ref, ++func_ref)
			{
				if (IMAGE_SNAP_BY_ORDINAL(thunk_ref->u1.Ordinal))
				{
					if (NT_FAIL(f->LdrGetProcedureAddress(h_dll, NULL, IMAGE_ORDINAL(thunk_ref->u1.Ordinal), (void**)&func_ref->u1.Function)))
					{
						err_break = true;
						goto ERR_BREAK;
					}
				}
				else
				{
					IMAGE_IMPORT_BY_NAME* _import = (IMAGE_IMPORT_BY_NAME*)(thunk_ref->u1.AddressOfData + image_base);

					ANSI_STRING* ansi_str = _HeapAlloc<ANSI_STRING>(f, 1);

					if (!ansi_str)
					{
						err_break = true;
						goto ERR_BREAK;
					}

					ansi_str->Length = _strlen(_import->Name);

					if (ansi_str->Length == -1)
					{
						_FreeHeap(f, ansi_str);
					
						err_break = true;
						goto ERR_BREAK;
					}

					ansi_str->szBuffer   = _import->Name;
					ansi_str->MaxLength  = ansi_str->Length + 1 * sizeof(char);
					
					if (NT_FAIL(f->LdrGetProcedureAddress(h_dll, ansi_str, NULL, (void**)&func_ref->u1.Function)))
					{
						_FreeHeap(f, ansi_str);

						err_break = true;
						goto ERR_BREAK;
					}

					_FreeHeap(f, ansi_str);
				}
			}
			++import_descriptor;
		}

		ERR_BREAK:
		if (err_break)
		{
			DeleteAllDependencies(f, imports);
		
			image_size = 0;
			f->NtFreeVirtualMemory(h_proc, (void**)&image_base, &image_size, MEM_RELEASE);

			return 0;
		}
	}

	if (opt_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size)
	{
		IMAGE_TLS_DIRECTORY* TLS_dir	   = (IMAGE_TLS_DIRECTORY*)(opt_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress + image_base);
		PIMAGE_TLS_CALLBACK* TLS_callback  = (PIMAGE_TLS_CALLBACK*)(TLS_dir->AddressOfCallBacks + image_base);

		for (; TLS_callback && *TLS_callback; ++TLS_callback)
		{
			(*TLS_callback)(image_base, DLL_PROCESS_ATTACH, NULL);
		}
	}

	ULONG		state   = 0;
	ULONG_PTR	cookie  = 0;
	bool		locked  = false;
	bool		failed  = false;

	locked = f->LdrLockLoaderLock(NULL, &state, &cookie) == 0;

	if (!DllMain((HINSTANCE)image_base, DLL_PROCESS_ATTACH, NULL))
	{
		failed = true;
	}

	if (locked)
	{
		f->LdrUnlockLoaderLock(NULL, cookie);
	}

	if (failed)
	{
		DeleteAllDependencies(f, imports);

		image_size = 0;
		f->NtFreeVirtualMemory(h_proc, (void**)&image_base, &image_size, MEM_RELEASE);

		return 0;
	}

	mp_data->out_module_base = (HMODULE)image_base;

	return 1;
}

DWORD CODE_SEG(".mmap_seg$2") __stdcall ManualMapShellEnd()
{
	return 0;
}

MANUAL_MAP_FUNCTION_TABLE::MANUAL_MAP_FUNCTION_TABLE()
{
	INIT_CONSTRUCTOR_NATIVE(LdrGetProcedureAddress);
	//INIT_CONSTRUCTOR_NATIVE(LdrLoadDll);
	//INIT_CONSTRUCTOR_NATIVE(LdrUnloadDll);
	INIT_CONSTRUCTOR_NATIVE(RtlFreeHeap);
	INIT_CONSTRUCTOR_NATIVE(LdrpHeap);
	INIT_CONSTRUCTOR_NATIVE(RtlAllocateHeap);
	INIT_CONSTRUCTOR_NATIVE(NtAllocateVirtualMemory);
	INIT_CONSTRUCTOR_NATIVE(NtFreeVirtualMemory);
	INIT_CONSTRUCTOR_NATIVE(memmove);
	INIT_CONSTRUCTOR_NATIVE(NtOpenFile);
	INIT_CONSTRUCTOR_NATIVE(NtClose);
	INIT_CONSTRUCTOR_NATIVE(NtSetInformationFile);
	INIT_CONSTRUCTOR_NATIVE(NtQueryInformationFile);
	INIT_CONSTRUCTOR_NATIVE(NtReadFile);
	INIT_CONSTRUCTOR_NATIVE(LdrLockLoaderLock);
	INIT_CONSTRUCTOR_NATIVE(LdrUnlockLoaderLock);

	INIT_CONSTRUCTOR_NATIVE_WIN32(LoadLibraryA);
	INIT_CONSTRUCTOR_NATIVE_WIN32(FreeLibrary);
}

MANUAL_MAPPING_SHELL_DATA::MANUAL_MAPPING_SHELL_DATA(INJECTION_DATA* data)
{
	flags = data->flags;

	wcscat(dll_path, L"\\??\\");
	wcscat(dll_path, data->dll_path);
}