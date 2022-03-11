#include "includes.hpp"

DLLEXPORT int WINAPI Start(INJECTION_DATA* data)
{
	bool fail_flag = false;
	wchar_t* windows_dir = nullptr;
	std::wstring ntdll_path;
	SymbolLoader loader;

	g_h_current_module = data->start_args.hinstance;

	if (!GetOwnModuleFolderPathW(g_path_to_this_module_folder, sizeof(g_path_to_this_module_folder)))
	{
		ERRLOG("Cannot get own module folder path");

		fail_flag = true;

		goto FINISH;
	}

	if (!GetOwnModuleFullPathW(g_path_to_this_module, sizeof(g_path_to_this_module)))
	{
		ERRLOG("Cannot get own module full path");

		fail_flag = true;

		goto FINISH;
	}

	if (_wdupenv_s(&windows_dir, nullptr, L"WINDIR") || !windows_dir)
	{
		if (windows_dir)
		{
			free(windows_dir);
		}

		fail_flag = true;

		goto FINISH;
	}

	ntdll_path = windows_dir;
	ntdll_path += L"\\System32\\ntdll.dll";

	free(windows_dir);

	if (!loader.Initialize(ntdll_path.c_str(), g_path_to_this_module_folder, false, SL_DEFAULT_TIMEOUT))
	{
		ERRLOG("Cannot initialize ntdll.pdb file");
		
		fail_flag = true;

		goto FINISH;
	}

	if (!ResolveImports(&loader))
	{
		ERRLOG("Cannot resolve imports");

		fail_flag = true;

		goto FINISH;
	}

	if (!Inject(data))
	{
		ERRLOG("Inject error");

		fail_flag = true;

		goto FINISH;
	}

FINISH:

	g_executing_finished = true;

	if (fail_flag)
	{
		LOG("Executing finished with failure!");

		return 0;
	}

	LOG("Executing finished successfully!");
	
	return 1;
}

BOOL WINAPI DllMain(HINSTANCE inst, DWORD reason, LPVOID reserved)
{
	switch (reason)
	{
	case DLL_PROCESS_ATTACH:
		break;
	case DLL_PROCESS_DETACH:
		break;
	case DLL_THREAD_ATTACH:
		break;
	case DLL_THREAD_DETACH:
		break;
	default:
		return FALSE;
	}

	return TRUE;
}