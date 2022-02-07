#include "includes.hpp"

bool SymbolLoader::VerifyExistingPDB(const GUID* guid)
{
	std::fstream file(pdb_path, std::ios::in | std::ios::binary | std::ios::ate);

	if (!file.good())
	{
		return false;
	}
	
	size_t file_size = (size_t)file.tellg();

	if (!file_size || file_size < sizeof(PDBHeader))
	{
		file.close();

		return false;
	}

	BYTE* file_raw = new BYTE[file_size];

	if (!file_raw)
	{
		file.close();

		return false;
	}

	file.seekg(0, std::ios::beg);
	file.read((char*)file_raw, file_size);
	file.close();

	PDBHeader* pdb_header = (PDBHeader*)file_raw;

	if (memcmp(pdb_header->signature, "Microsoft C/C++ MSF 7.00\r\n\x1A""DS\0\0\0", sizeof(pdb_header->signature) / sizeof(pdb_header->signature[0])))
	{
		delete[file_size] file_raw;

		return false;
	}

	if (file_size < pdb_header->page_size * pdb_header->num_of_file_pages)
	{
		delete[file_size] file_raw;

		return false;
	}

	int*            root_page_number  = (int*)(file_raw + pdb_header->page_number_of_root_stream_number_list * pdb_header->page_size);
	PDBRootStream*  root_stream       = (PDBRootStream*)(file_raw + *root_page_number * pdb_header->page_size);

	std::map<int, std::vector<int>> streams;

	int current_page_number = 0;
	for (int i = 0; i < root_stream->num_of_streams; ++i)
	{
		int current_stream_size         = root_stream->stream_size[i] == 0xFFFFFFFF ? 0 : root_stream->stream_size[i];
		int current_stream_pages_count  = current_stream_size / pdb_header->page_size;

		if (current_stream_size % pdb_header->page_size)
		{
			++current_stream_pages_count;
		}

		std::vector<int> numbers;

		for (int j = 0; j < current_stream_pages_count; ++j, ++current_page_number)
		{
			numbers.push_back(root_stream->stream_size[root_stream->num_of_streams + current_page_number]); // stream_page_number_list[current_page_number]
		}

		streams.insert(std::make_pair(i, numbers));
	}

	int pdb_info_page_index = 0;
	try
	{
		pdb_info_page_index = streams.at(1).at(0);
	}
	catch (const std::exception& ex)
	{
		ERRLOG("%s", ex.what());
		
		delete[file_size] file_raw;

		return false;
	}

	PDBinfoStream1* pdb_info = (PDBinfoStream1*)(file_raw + pdb_info_page_index * pdb_header->page_size);
	
	GUID pdb_GUID = pdb_info->guid;

	delete[file_size] file_raw;

	return (memcmp(&pdb_GUID, guid, sizeof(GUID)) == FALSE);
}

bool SymbolLoader::Initialize(const wchar_t* dll_path, const wchar_t* pdb_path, bool redownload, DWORD connect_timeout)
{
	is_ready = false;

	if (!dll_path || !pdb_path)
	{
		return false;
	}

	this->dll_path = dll_path;
	this->pdb_path = pdb_path;

	std::fstream file(dll_path, std::ios::in | std::ios::binary | std::ios::ate);

	if (!file.good())
	{
		return false;
	}

	size_t file_size = (size_t)file.tellg();

	if (!file_size)
	{
		file.close();

		return false;
	}

	BYTE* file_raw = new BYTE[file_size];

	if (!file_raw)
	{
		file.close();

		return false;
	}

	file.seekg(0, std::ios::beg);
	file.read((char*)file_raw, file_size);
	file.close();

	IMAGE_DOS_HEADER*         dos_header    = nullptr;
	IMAGE_NT_HEADERS*         pe_header     = nullptr;
	IMAGE_FILE_HEADER*		  file_header   = nullptr;
	IMAGE_OPTIONAL_HEADER32*  opt_header86  = nullptr;
	IMAGE_OPTIONAL_HEADER64*  opt_header64  = nullptr;

	dos_header = (IMAGE_DOS_HEADER*)file_raw;

	if (dos_header->e_magic != IMAGE_DOS_SIGNATURE)
	{
		delete[file_size] file_raw;

		return false;
	}

	pe_header = (IMAGE_NT_HEADERS*)(file_raw + dos_header->e_lfanew);

	if (pe_header->Signature != IMAGE_NT_SIGNATURE)
	{
		delete[file_size] file_raw;

		return false;
	}

	bool x86 = false;

	file_header = &pe_header->FileHeader;

	if (file_header->Machine == IMAGE_FILE_MACHINE_I386)
	{
		x86 = true;

		opt_header86 = (IMAGE_OPTIONAL_HEADER32*)&pe_header->OptionalHeader;
	}
	else if (file_header->Machine == IMAGE_FILE_MACHINE_AMD64)
	{
		opt_header64 = (IMAGE_OPTIONAL_HEADER64*)&pe_header->OptionalHeader;
	}
	else
	{
		delete[file_size] file_raw;

		return false;
	}

	DWORD image_size = x86 ? opt_header86->SizeOfImage : opt_header64->SizeOfImage;

	if (!image_size)
	{
		delete[file_size] file_raw;

		return false;
	}

	BYTE* local_image_base = new BYTE[image_size];
	
	if (!local_image_base)
	{
		delete[file_size] file_raw;

		return false;
	}

	IMAGE_SECTION_HEADER* first_section = IMAGE_FIRST_SECTION(pe_header);

	if (!first_section)
	{
		delete[file_size] file_raw;
		delete[image_size] local_image_base;

		return false;
	}

	for (DWORD i = 0; i < file_header->NumberOfSections; ++i)
	{
		if (first_section->SizeOfRawData)
		{
			memcpy(local_image_base + first_section->VirtualAddress, file_raw + first_section->PointerToRawData, first_section->SizeOfRawData);
		}
	}

	IMAGE_DATA_DIRECTORY* data_dir = nullptr;

	if (x86)
	{
		data_dir = &opt_header86->DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
	}
	else
	{
		data_dir = &opt_header64->DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
	}

	if (!data_dir->Size)
	{
		delete[image_size] local_image_base;
		delete[file_size] file_raw;

		return false;
	}

	IMAGE_DEBUG_DIRECTORY* debug_dir = (IMAGE_DEBUG_DIRECTORY*)(local_image_base + data_dir->VirtualAddress);

	if (debug_dir->Type != IMAGE_DEBUG_TYPE_CODEVIEW)
	{
		delete[image_size] local_image_base;
		delete[file_size] file_raw;

		return false;
	}

	PDBinfo* pdb_info = (PDBinfo*)(local_image_base + debug_dir->AddressOfRawData);

	if (pdb_info->signature != PDB_INFO_SIGNATURE)
	{
		delete[image_size] local_image_base;
		delete[file_size] file_raw;

		return false;
	}

	GUID pdb_GUID = pdb_info->guid;
	DWORD pdb_age = pdb_info->age;

	std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> conv;
	
	std::wstring pdb_file_name = conv.from_bytes(pdb_info->pdb_file_name);

	delete[image_size] local_image_base;
	delete[file_size] file_raw;

	pdb_info = nullptr;

	if (pdb_file_name.empty())
	{
		return false;
	}

	if (this->pdb_path[this->pdb_path.size() - 1] != '\\')
	{
		this->pdb_path += '\\';
	}

	if (!CreateDirectoryW(this->pdb_path.c_str(), NULL))
	{
		if (GetLastError() == ERROR_PATH_NOT_FOUND)
		{
			return false;
		}
	}

	this->pdb_path += x86 ? L"x86\\" : L"x64\\";

	if (!CreateDirectoryW(this->pdb_path.c_str(), NULL))
	{
		if (GetLastError() == ERROR_PATH_NOT_FOUND)
		{
			return false;
		}
	}

	this->pdb_path += pdb_file_name;

	WIN32_FILE_ATTRIBUTE_DATA file_data = { 0 };
	if (GetFileAttributesExW(this->pdb_path.c_str(), GET_FILEEX_INFO_LEVELS::GetFileExInfoStandard, &file_data))
	{
		if (!redownload && !VerifyExistingPDB(&pdb_GUID))
		{
			redownload = true;
		}

		if (redownload)
		{
			DeleteFileW(this->pdb_path.c_str());
		}
		else
		{
			pdb_size = file_data.nFileSizeLow;
		}
	}
	else
	{
		redownload = true;
	}

	if (redownload)
	{
		wchar_t w_GUID[100] = { 0 };
		if (!StringFromGUID2(pdb_GUID, w_GUID, 100))
		{
			return false;
		}
	
		std::wstring GUID_filtered;
		for (DWORD i = 0; w_GUID[i]; ++i)
		{
			if ((w_GUID[i] >= '0' && w_GUID[i] <= '9') || (w_GUID[i] >= 'A' && w_GUID[i] <= 'F') || (w_GUID[i] >= 'a' && w_GUID[i] <= 'f'))
			{
				GUID_filtered += w_GUID[i];
			}
		}

		std::wstring url = L"https://msdl.microsoft.com/download/symbols/";
		url += pdb_file_name;
		url += '/';
		url += GUID_filtered;
		url += std::to_wstring(pdb_age);
		url += '/';
		url += pdb_file_name;

		bool connected = false;

		ULONGLONG tick = GetTickCount64();
		do
		{
			if (InternetCheckConnectionW(L"https://msdl.microsoft.com", FLAG_ICC_FORCE_CONNECTION, NULL) == FALSE)
			{
				if (GetLastError() == ERROR_INTERNET_CANNOT_CONNECT)
				{
					return false;
				}
			}
			else
			{
				connected = true;

				break;
			}

			Sleep(25);
		} while (GetTickCount64() - tick <= connect_timeout);

		if (!connected)
		{
			return false;
		}

		wchar_t cache_file[MAX_PATH] = { 0 };

		if (FAILED(URLDownloadToCacheFileW(NULL, url.c_str(), cache_file, MAX_PATH, NULL, NULL)))
		{
			if (cache_file[0] != '\0')
			{
				DeleteFileW(cache_file);
			}

			return false;
		}

		if (!CopyFileW(cache_file, this->pdb_path.c_str(), FALSE))
		{
			DeleteFileW(cache_file);
			
			return false;
		}

		DeleteFileW(cache_file);
	}

	if (!pdb_size)
	{
		if (!GetFileAttributesExW(this->pdb_path.c_str(), GET_FILEEX_INFO_LEVELS::GetFileExInfoStandard, &file_data))
		{
			return false;
		}

		pdb_size = file_data.nFileSizeLow;
	}

	is_ready = true;

	return true;
}

bool SymbolLoader::IsReady() const
{
	return is_ready;
}

void SymbolLoader::Cleanup()
{
	dll_path = { 0 };
	pdb_path = { 0 };

	pdb_size = 0;

	is_ready = false;
}

size_t SymbolLoader::GetPDBSize() const
{
	return pdb_size;
}

std::wstring SymbolLoader::GetPDBPath() const
{
	return pdb_path;
}

std::wstring SymbolLoader::GetDLLPath() const
{
	return dll_path;
}