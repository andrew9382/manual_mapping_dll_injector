#include "includes.hpp"

DWORD GetProcId(const wchar_t* proc_name)
{
	DWORD proc_id = NULL;
	HANDLE h_snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

	PROCESSENTRY32 p_entry = { 0 };
	p_entry.dwSize = sizeof(p_entry);

	if (h_snap == INVALID_HANDLE_VALUE)
	{
		ERRLOG("CreateToolhelp32Snapshot: % d\n", GetLastError());
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

DWORD GetOwnModuleFullPathW(fs::path& mod_name_path)
{
	wchar_t mod_name_buf[MAX_PATH] = { 0 };

	DWORD mod_name_len = GetModuleFileNameW(g_h_current_module, mod_name_buf, sizeof(mod_name_buf) / sizeof(mod_name_buf[0]));

	if (!mod_name_len || GetLastError() == ERROR_INSUFFICIENT_BUFFER)
	{
		return 0;
	}

	mod_name_path = mod_name_buf;

	return mod_name_len;
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

	if (!file_raw)
	{
		file.close();

		return false;
	}

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

DWORD IsElevatedProcess(HANDLE h_proc)
{
	HANDLE h_token = 0;
	if (!OpenProcessToken(h_proc, TOKEN_QUERY, &h_token))
	{
		return -1;
	}

	TOKEN_ELEVATION te = { 0 };
	DWORD size_out = 0;
	if (!GetTokenInformation(h_token, TOKEN_INFORMATION_CLASS::TokenElevation, &te, sizeof(te), &size_out))
	{
		CloseHandle(h_token);
		
		return -1;
	}
	
	CloseHandle(h_token);

	return te.TokenIsElevated != 0;
}

int _random(int begin, int end)
{
	return begin + rand() % (end - begin + 1);
}