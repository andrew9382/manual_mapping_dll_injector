#pragma once

class SymbolParser
{
private:

	HANDLE   h_proc       = 0;
	DWORD64  sym_table    = 0;
	bool	 initialized  = false;
	bool	 is_ready     = false;

public:

	~SymbolParser();

	bool Cleanup();

	bool Initialize(const SymbolLoader* loader);

	DWORD GetSymbolAddress(const wchar_t* sym_name);

	bool IsReady();
};

inline SymbolParser sym_parser;