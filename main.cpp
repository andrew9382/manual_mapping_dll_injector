#include "includes.hpp"

const wchar_t dll_name[] = L"C:\\Users\\Andrew\\Desktop\\Programming\\cpp\\garbage\\test_dll\\Debug\\test_dll.dll";
const wchar_t proc_name[] = L"test_for_injection.exe";

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PWSTR pCmdLine, int nCmdShow)
{
	if (!AllocConsole())
	{
		return 1;
	}

	if (!SetConsoleTitleW(L"manual_map_injector.exe"))
	{
		return 1;
	}

	FILE* console = nullptr;
	if (freopen_s(&console, "CONOUT$", "w", stdout) || !console)
	{
		if (console)
		{
			fclose(console);
		}

		return 1;
	}
	
	g_h_current_module = hInstance;

	wchar_t current_module_path[MAX_PATH * 2] = { 0 };
	if (!GetOwnModulePathW(current_module_path, MAX_PATH * 2))
	{
		fclose(console);

		ERRLOG("Cannot get own module path");

		return 1;
	}

	wchar_t* windows_dir = nullptr;
	if (_wdupenv_s(&windows_dir, nullptr, L"WINDIR") || !windows_dir)
	{
		if (windows_dir)
		{
			free(windows_dir);
		}

		fclose(console);

		return 1;
	}

	std::wstring ntdll_path = windows_dir;
	ntdll_path += L"\\System32\\ntdll.dll";

	free(windows_dir);

	SymbolLoader loader;

	if (!loader.Initialize(ntdll_path.c_str(), current_module_path, false, SL_DEFAULT_TIMEOUT))
	{
		ERRLOG("Cannot initialize ntdll.pdb file");
		
		fclose(console);

		return 1;
	}

	if (!ResolveImports(&loader))
	{
		ERRLOG("Cannot resolve imports");

		fclose(console);

		return 1;
	}

	DWORD proc_id = GetProcId(proc_name);
	if (!proc_id)
	{
		ERRLOG("Cannot get process id");
		
		fclose(console);

		return 1;
	}

	HANDLE h_proc = OpenProcess(PROCESS_ALL_ACCESS, NULL, proc_id);

	INJECTION_DATA data;
	data.h_proc = h_proc;
	data.flags |= INJ_CTX_ALL;
	wcscpy(data.dll_path, dll_name);
	data.method = LAUNCH_METHOD::LM_NT_CREATE_THREAD_EX;

	if (!Inject(&data))
	{
		ERRLOG("Inject error");
		
		fclose(console);

		return 1;
	}

	fclose(console);

	return 0;
}