#include "includes.hpp"

DWORD GetProcId(const wchar_t* proc_name)
{
	DWORD proc_id = NULL;
	HANDLE h_snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	PROCESSENTRY32 p_entry = { 0 };
	p_entry.dwSize = sizeof(p_entry);

	if (h_snap == INVALID_HANDLE_VALUE)
	{
		printf("[ERROR] CreateToolhelp32Snapshot: %d\n", GetLastError());
		return NULL;
	}
	if (Process32First(h_snap, &p_entry))
	{
		do
		{
			if (!wcscmp(proc_name, p_entry.szExeFile))
			{
				proc_id = p_entry.th32ProcessID;
				break;
			}
		} while (Process32Next(h_snap, &p_entry));
	}

	CloseHandle(h_snap);
	return proc_id;
}

DWORD GetOwnModulePathW(wchar_t* mod_name_buf, size_t buf_size)
{
	DWORD mod_name_len = GetModuleFileNameW(g_h_current_module, mod_name_buf, buf_size);

	if (!mod_name_len || GetLastError() == ERROR_INSUFFICIENT_BUFFER)
	{
		return 0;
	}

	mod_name_buf += mod_name_len;
	while (*(--mod_name_buf - 1) != '\\');
	*mod_name_buf = '\0';

	return mod_name_len;
}

bool FileExists(const wchar_t* file_path)
{
	return (GetFileAttributesW(file_path) != INVALID_FILE_ATTRIBUTES);
}

bool VerifyDLL(const wchar_t* file_path, WORD desired_machine)
{
	if (!file_path)
	{
		return false;
	}

	std::fstream file(file_path, std::ios::in | std::ios::binary | std::ios::ate);

	if (!file.good())
	{
		return false;
	}

	DWORD file_size = (DWORD)file.tellg();

	if (!file_size || file_size < PAGE_SIZE)
	{
		file.close();

		return false;
	}

	BYTE* file_raw = new BYTE[PAGE_SIZE];

	file.seekg(0, std::ios::beg);
	file.read((char*)file_raw, PAGE_SIZE);
	file.close();

	IMAGE_DOS_HEADER*		dos_header   = nullptr;
	IMAGE_NT_HEADERS*		pe_header    = nullptr;
	IMAGE_FILE_HEADER*		file_header  = nullptr;

	dos_header = (IMAGE_DOS_HEADER*)file_raw;

	if (dos_header->e_magic != IMAGE_DOS_SIGNATURE || dos_header->e_lfanew > PAGE_SIZE)
	{
		delete[PAGE_SIZE] file_raw;

		return false;
	}

	pe_header = (IMAGE_NT_HEADERS*)(file_raw + dos_header->e_lfanew);

	if (pe_header->Signature != IMAGE_NT_SIGNATURE)
	{
		delete[PAGE_SIZE] file_raw;

		return false;
	}

	file_header = &pe_header->FileHeader;

	if (!(file_header->Machine & desired_machine) || !(file_header->Characteristics & IMAGE_FILE_DLL))
	{
		delete[PAGE_SIZE] file_raw;

		return false;
	}

	delete[PAGE_SIZE] file_raw;

	return true;
}

bool IsNativeProcess(HANDLE h_proc)
{
	BOOL wow64 = FALSE;
	IsWow64Process(h_proc, &wow64);

	return (wow64 == FALSE);
}