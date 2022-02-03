#include "includes.hpp"

DWORD __stdcall CODE_SEG(".mmap_seg$1") ManualMapShell(MANUAL_MAPPING_SHELL_DATA* mp_data)
{
	if (!mp_data)
	{
		return 0;
	}

	MANUAL_MAP_FUNCTION_TABLE* f = &mp_data->f_table;

	if (!f)
	{
		return 0;
	}

	f->p_LdrpHeap = *f->LdrpHeap;
	if (!f->p_LdrpHeap)
	{
		return 0;
	}

	BYTE* base = (BYTE*)mp_data;
	IMAGE_OPTIONAL_HEADER* opt_header = (IMAGE_OPTIONAL_HEADER*)&(((IMAGE_NT_HEADERS*)(((IMAGE_DOS_HEADER*)(base))->e_lfanew + base)))->OptionalHeader;

	BYTE* location_delta = base - opt_header->ImageBase;
	if (location_delta)
	{
		if (!opt_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size)
			return;

		IMAGE_BASE_RELOCATION* reloc_data = (IMAGE_BASE_RELOCATION*)(base + opt_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
		while (reloc_data->VirtualAddress)
		{
			DWORD amount_of_entries = (reloc_data->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
			WORD* relative_info = (WORD*)(reloc_data + 1);

			for (DWORD i = 0; i < amount_of_entries; ++i, ++relative_info)
			{
				if (RELOC_FLAG(*relative_info))
				{
					DWORD* patch = (DWORD*)(base + reloc_data->VirtualAddress + (*relative_info & 0xFFF));
					*patch += (DWORD)location_delta;
				}
			}
			reloc_data = (IMAGE_BASE_RELOCATION*)((BYTE*)reloc_data + reloc_data->SizeOfBlock);
		}
	}

	if (opt_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size)
	{
		IMAGE_IMPORT_DESCRIPTOR* import_descriptor = (IMAGE_IMPORT_DESCRIPTOR*)(opt_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress + base);

		while (import_descriptor->Name)
		{
			char* dll_name = (char*)(base + import_descriptor->Name);
			HINSTANCE h_dll = _LoadLibraryA(dll_name);

			DWORD* thunk_ref = (DWORD*)(base + import_descriptor->OriginalFirstThunk);
			DWORD* func_ref = (DWORD*)(base + import_descriptor->FirstThunk);

			if (!thunk_ref)
				thunk_ref = func_ref;

			for (; *thunk_ref; ++thunk_ref, ++func_ref)
			{
				if (IMAGE_SNAP_BY_ORDINAL(*thunk_ref))
				{
					*func_ref = _GetProcAddress(h_dll, (char*)(*thunk_ref & 0xFFFF));
				}
				else
				{
					IMAGE_IMPORT_BY_NAME* _import = (IMAGE_IMPORT_BY_NAME*)(*thunk_ref + base);
					*func_ref = _GetProcAddress(h_dll, _import->Name);
				}
			}
			++import_descriptor;
		}
	}

	if (opt_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size)
	{
		IMAGE_TLS_DIRECTORY* TLS = (IMAGE_TLS_DIRECTORY*)(opt_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress + base);
		PIMAGE_TLS_CALLBACK* TLS_callback = (PIMAGE_TLS_CALLBACK*)(TLS->AddressOfCallBacks + base);

		for (; TLS_callback && *TLS_callback; ++TLS_callback)
			(*TLS_callback)(base, DLL_PROCESS_ATTACH, NULL);
	}

	_DllMain((HINSTANCE)base, DLL_PROCESS_ATTACH, NULL);

	mp_data->h_module = (HINSTANCE)base;

	return 1;
}

DWORD __stdcall CODE_SEG(".mmap_seg$2") ManualMapShellEnd()
{
	return 0;
}

MANUAL_MAP_FUNCTION_TABLE::MANUAL_MAP_FUNCTION_TABLE()
{
	ADDR_FROM_NATIVE(LdrGetProcedureAddress);
	ADDR_FROM_NATIVE(LdrLoadDll);
	ADDR_FROM_NATIVE(RtlFreeHeap);
	ADDR_FROM_NATIVE(LdrpHeap);
	ADDR_FROM_NATIVE(RtlAllocateHeap);
	ADDR_FROM_NATIVE(NtAllocateVirtualMemory);
	ADDR_FROM_NATIVE(NtFreeVirtualMemory);
	ADDR_FROM_NATIVE(memmove);
	ADDR_FROM_NATIVE(NtOpenFile);
	ADDR_FROM_NATIVE(NtClose);
	ADDR_FROM_NATIVE(NtSetInformationFile);
	ADDR_FROM_NATIVE(NtQueryInformationFile);
	ADDR_FROM_NATIVE(NtReadFile);
}

MANUAL_MAPPING_SHELL_DATA::MANUAL_MAPPING_SHELL_DATA(INJECTION_DATA* data)
{
	h_proc = data->h_proc;
	flags = data->flags;

	wcscpy(dll_path, data->dll_path);
}