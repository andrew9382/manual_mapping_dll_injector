#include "includes.hpp"

SymbolParser::~SymbolParser()
{
	Cleanup();
}

bool SymbolParser::Cleanup()
{
	if (initialized)
	{
		if (sym_table)
		{
			SymUnloadModule64(h_proc, sym_table);

			sym_table = 0;
		}

		SymCleanup(h_proc);

		initialized = false;
	}

	if (h_proc)
	{
		CloseHandle(h_proc);

		h_proc = 0;
	}

	is_ready = false;

	return true;
}

bool SymbolParser::Initialize(const SymbolLoader* loader)
{
	is_ready = false;
	
	if (!loader)
	{
		return false;
	}

	if (!loader->IsReady())
	{
		return false;
	}

	if (sym_table)
	{
		if (!SymUnloadModule64(h_proc, sym_table))
		{
			return false;
		}

		sym_table = 0;
	}

	if (!h_proc)
	{
		h_proc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, NULL, GetCurrentProcessId());

		if (!h_proc)
		{
			return false;
		}
	}

	if (!initialized)
	{
		SymSetOptions(SYMOPT_UNDNAME | SYMOPT_AUTO_PUBLICS | SYMOPT_DEFERRED_LOADS);

		if (!SymInitialize(h_proc, NULL, NULL))
		{
			CloseHandle(h_proc);

			return false;
		}

		initialized = true;
	}

	sym_table = SymLoadModuleExW(h_proc, NULL, loader->GetPDBPath().c_str(), NULL, 0x10000000, loader->GetPDBSize(), NULL, NULL);
	if (!sym_table)
	{
		SymCleanup(h_proc);

		CloseHandle(h_proc);

		initialized = false;

		return false;
	}

	is_ready = true;

	return true;
}

DWORD SymbolParser::GetSymbolAddress(const wchar_t* sym_name)
{
	if (!is_ready)
	{
		return 0;
	}

	if (!sym_name)
	{
		return 0;
	}

	SYMBOL_INFOW si = { 0 };
	si.SizeOfStruct = sizeof(si);
	if (!SymFromNameW(h_proc, sym_name, &si))
	{
		return 0;
	}

	return (DWORD)(si.Address - si.ModBase);
}

bool SymbolParser::IsReady()
{
	return is_ready;
}
