#pragma once

// macro to convert 64-types into a DWORD without triggereing C4302 or C4311 (also works on 32-bit sized pointers)
#define MDWD(t) ((DWORD)(ULONG_PTR)t & 0xFFFFFFFF)

#define JMP_DST(dst, src) ((DWORD)dst - ((DWORD)src + 5))

#define PAGE_SIZE 0x1000

#define _LOG(format, type, ...) printf("[ "##type" ] "##format"\n", __VA_ARGS__)
#define ERRLOG(format, ...) _LOG(format, "ERROR", __VA_ARGS__)
#define SUCCLOG(format, ...) _LOG(format, "SUCCESS", __VA_ARGS__)
#define LOG(format, ...) _LOG(format, "LOG", __VA_ARGS__)

#define CODE_SEG(seg_name) __declspec(code_seg(seg_name))

#define SUSP_ERR(dword) ((DWORD)dword == -1)

#define _ZeroMemory(ptr, size) memset(ptr, 0, size)

#define ALIGN_64 __declspec(align(8))
#define ALIGN_86 __declspec(align(4))

#ifdef _WIN64
#define ALIGN ALIGN_64
#else
#define ALIGN ALIGN_86
#endif

DWORD GetProcId(const wchar_t* proc_name);

DWORD GetOwnModuleFullPathW(fs::path& mod_name_path);

bool VerifyDLL(const wchar_t* file_path, WORD desired_machine);

bool IsNativeProcess(HANDLE h_proc);

DWORD IsElevatedProcess(HANDLE h_proc);

int _random(int begin, int end);

__forceinline DWORD bit_rotate_r(DWORD val, int count)
{
	return (val >> count) | (val << (-count));
}

__forceinline DWORD bit_rotate_l(DWORD val, int count)
{
	return (val << count) | (val >> (-count));
}

#define EncodeSystemPtr_64(ptr) (bit_rotate_r((*P_KUSER_SHARED_DATA_COOKIE) ^ ptr, (*P_KUSER_SHARED_DATA_COOKIE) & 0x3F))
#define EncodeSystemPtr_32(ptr) (bit_rotate_r((*P_KUSER_SHARED_DATA_COOKIE) ^ ptr, (*P_KUSER_SHARED_DATA_COOKIE) & 0x1F))

#define DecodeSystemPtr_64(ptr) (bit_rotate_l(ptr, (*P_KUSER_SHARED_DATA_COOKIE) & 0x3F) ^ (*P_KUSER_SHARED_DATA_COOKIE))
#define DecodeSystemPtr_32(ptr) (bit_rotate_l(ptr, (*P_KUSER_SHARED_DATA_COOKIE) & 0x1F) ^ (*P_KUSER_SHARED_DATA_COOKIE))

#ifdef _WIN64
#define DecodeSystemPtr DecodeSystemPtr_64
#define EncodeSystemPtr EncodeSystemPtr_64
#else
#define DecodeSystemPtr DecodeSystemPtr_32
#define EncodeSystemPtr EncodeSystemPtr_32
#endif