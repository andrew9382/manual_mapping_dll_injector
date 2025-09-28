#pragma once

#define PDB_INFO_SIGNATURE 0x53445352
#define SL_DEFAULT_TIMEOUT 10000

class SymbolLoader
{
private:

	std::wstring dll_path = { 0 };
	std::wstring pdb_path = { 0 };

	bool    is_ready = false;
	size_t  pdb_size = 0;

	bool VerifyExistingPDB(const GUID* guid);

public:

	bool Initialize(const wchar_t* dll_path, const wchar_t* pdb_path, bool redownload, DWORD connect_timeout);

	bool IsReady() const;

	void Cleanup();

	size_t		  GetPDBSize() const;
	std::wstring  GetPDBPath() const;
	std::wstring  GetDLLPath() const;
};

struct PDBinfo
{
	DWORD  signature;
	GUID   guid;
	DWORD  age;
	char   pdb_file_name[ANYSIZE_ARRAY];
};

struct PDBHeader
{
	char signature[0x20];
	int page_size;
	int alloc_table_ptr;
	int num_of_file_pages;
	int root_stream_size;
	int reserved;
	int page_number_of_root_stream_number_list;
};

struct PDBRootStream
{
	int num_of_streams;
	int stream_size[ANYSIZE_ARRAY]; // num_of_streams
 // int stream_page_number_list[ANYSIZE_ARRAY]
};

struct PDBinfoStream1
{
	int version;
	int time_date_stamp;
	int age;
	GUID guid;
};