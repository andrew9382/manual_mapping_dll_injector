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

#define ZeroMem(ptr) memset(ptr, 0, sizeof(*(ptr))) 

#define ALIGN_64 __declspec(align(8))
#define ALIGN_86 __declspec(align(4))

#ifdef _WIN64
#define ALIGN ALIGN_64
#else
#define ALIGN ALIGN_86
#endif