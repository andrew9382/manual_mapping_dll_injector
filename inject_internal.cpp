#include "includes.hpp"

INJECT_INTERNAL_FUNCTION_TABLE::INJECT_INTERNAL_FUNCTION_TABLE()
{
	INIT_CONSTRUCTOR_NATIVE(RtlRbRemoveNode);
	INIT_CONSTRUCTOR_NATIVE(memmove);
	INIT_CONSTRUCTOR_NATIVE(memset);
	INIT_CONSTRUCTOR_NATIVE(NtProtectVirtualMemory);
	INIT_CONSTRUCTOR_NATIVE(LdrpMappingInfoIndex);
	INIT_CONSTRUCTOR_NATIVE(LdrpModuleBaseAddressIndex);
	
	INIT_CONSTRUCTOR_NATIVE_WIN32(LoadLibraryExW);
	INIT_CONSTRUCTOR_NATIVE_WIN32(FreeLibrary);
	INIT_CONSTRUCTOR_NATIVE_WIN32(GetLastError);
}

DWORD CODE_SEG(".inj_int$1") __stdcall InjectInternal(INJECT_INTERNAL_DATA* data)
{
	if (!data)
	{
		return 0;
	}

	INJECT_INTERNAL_FUNCTION_TABLE* f = &data->f;
	DWORD flags = data->flags;

	HMODULE h_dll = f->p_LoadLibraryExW(data->dll_path, NULL, NULL);
	if (!h_dll)
	{
		data->last_error = f->p_GetLastError();

		return 0;
	}

	if (flags & (INJ_ERASE_HEADER | INJ_FAKE_HEADER))
	{
		HANDLE h_proc = NtCurrentProcess();

		DWORD old_protect = 0;
		SIZE_T size = PAGE_SIZE;

		data->last_error = f->NtProtectVirtualMemory(h_proc, (void**)&h_dll, &size, PAGE_EXECUTE_READWRITE, &old_protect);

		if (NT_FAIL(data->last_error))
		{
			f->p_FreeLibrary(h_dll);

			return 0;
		}

		if (flags & INJ_ERASE_HEADER)
		{
			f->_ZeroMemory(h_dll, size);
		}
		else
		{
			wchar_t nt_dll[10] = { 0 };

			nt_dll[0] = L'n';
			nt_dll[1] = L't';
			nt_dll[2] = L'd';
			nt_dll[3] = L'l';
			nt_dll[4] = L'l';
			nt_dll[5] = L'.';
			nt_dll[6] = L'd';
			nt_dll[7] = L'l';
			nt_dll[8] = L'l';
			nt_dll[9] = L'\0';

			HMODULE h_nt = f->p_LoadLibraryExW(nt_dll, NULL, NULL); // problem
			
			if (!h_nt)
			{
				data->last_error = f->p_GetLastError();

				f->p_FreeLibrary(h_dll);

				return 0;
			}

			f->memmove(h_dll, h_nt, size);

			f->p_FreeLibrary(h_nt);
		}

		data->last_error = f->NtProtectVirtualMemory(h_proc, (void**)&h_dll, &size, old_protect, &old_protect);

		if (NT_FAIL(data->last_error))
		{
			f->p_FreeLibrary(h_dll);

			return 0;
		}
	}

	if (flags & INJ_UNLINK_FROM_PEB)
	{

#ifdef _WIN64
		PEB* peb = (PEB*)__readgsqword(0x60);
#else
		PEB* peb = (PEB*)__readfsdword(0x30);
#endif

		if (!peb)
		{
			f->p_FreeLibrary(h_dll);

			return 0;
		}

		LIST_ENTRY* head		= &peb->Ldr->InLoadOrderModuleListHead;
		LIST_ENTRY* current		= peb->Ldr->InLoadOrderModuleListHead.Flink;

		while (current != head)
		{
			if (((LDR_DATA_TABLE_ENTRY*)current)->DllBase == h_dll)
			{
				break;
			}

			current = current->Flink;
		}

		if (((LDR_DATA_TABLE_ENTRY*)current)->DllBase != h_dll)
		{
			f->p_FreeLibrary(h_dll);

			return 0;
		}

		LDR_DATA_TABLE_ENTRY* entry = (LDR_DATA_TABLE_ENTRY*)current;

		UNLINK_IF(entry->InMemoryOrderLinks);
		UNLINK_IF(entry->InLoadOrderLinks);
		UNLINK_IF(entry->InInitializationOrderLinks);

		DWORD ldr_size		= 0;
		DWORD ddag_size		= 0;
		void* ddag			= nullptr;

		if (data->os_version == g_Win7)
		{
			LDR_DATA_TABLE_ENTRY_WIN7* entry_w7 = (LDR_DATA_TABLE_ENTRY_WIN7*)current;

			UNLINK_IF(entry_w7->ServiceTagLinks);
			UNLINK_IF(entry_w7->StaticLinks);
			UNLINK_IF(entry_w7->ForwarderLinks);

			ldr_size = sizeof(LDR_DATA_TABLE_ENTRY_WIN7);
		}
		else
		{
			f->RtlRbRemoveNode(f->LdrpModuleBaseAddressIndex,	&entry->BaseAddressIndexNode);
			f->RtlRbRemoveNode(f->LdrpMappingInfoIndex,			&entry->MappingInfoIndexNode);

			ddag = (void*)&entry->DdagNode;

			if (data->os_version == g_Win8)
			{
				ldr_size = sizeof(LDR_DATA_TABLE_ENTRY_WIN8);
				ddag_size = sizeof(LDR_DDAG_NODE_WIN8);
			}
			else if (data->os_version == g_Win81)
			{
				ldr_size = sizeof(LDR_DATA_TABLE_ENTRY_WIN81);
				ddag_size = sizeof(LDR_DDAG_NODE_WIN81);
			}
			else if (data->os_version >= g_Win10)
			{
				ddag_size = sizeof(LDR_DDAG_NODE_WIN10);

				if (data->os_build_version <= g_Win10_1511)
				{
					ldr_size = offsetof(LDR_DATA_TABLE_ENTRY_WIN10, DependentLoadFlags);
				}
				else if (data->os_build_version <= g_Win10_1607)
				{
					ldr_size = offsetof(LDR_DATA_TABLE_ENTRY_WIN10, SigningLevel);
				}
				else if (data->os_build_version <= g_Win10_21H2)
				{
					ldr_size = sizeof(LDR_DATA_TABLE_ENTRY_WIN10);
				}
				else
				{
					ldr_size = sizeof(LDR_DATA_TABLE_ENTRY_WIN11);
					ddag_size = sizeof(LDR_DDAG_NODE_WIN11);
				}
			}
		}

		f->_ZeroMemory(entry->BaseDllName.szBuffer, entry->BaseDllName.MaxLength);
		f->_ZeroMemory(entry->FullDllName.szBuffer, entry->FullDllName.MaxLength);

		f->_ZeroMemory(entry, ldr_size);

		if (ddag)
		{
			f->_ZeroMemory(ddag, ddag_size);
		}
	}

	data->h_dll_out = h_dll;

	return 1;
}

DWORD CODE_SEG(".inj_int$2") __stdcall InjectInternal_End()
{
	return 0;
}

INJECT_INTERNAL_DATA::INJECT_INTERNAL_DATA(INJECTION_DATA* data, DWORD os_ver, DWORD os_build_ver)
{
	wcscpy(dll_path, data->dll_path);
	flags = data->flags;
	os_version = os_ver;
	os_build_version = os_build_ver;
}