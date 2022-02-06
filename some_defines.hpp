#pragma once

// macro to convert 64-types into a DWORD without triggereing C4302 or C4311 (also works on 32-bit sized pointers)
#define MDWD(t) ((DWORD)(ULONG_PTR)t & 0xFFFFFFFF)

#define JMP_DST(dst, src) ((DWORD)dst - ((DWORD)src + 5))

#define PAGE_SIZE 0x1000

#define ERRLOG(format, ...) printf("[ ERROR ] "##format##"\n", __VA_ARGS__);

#define CODE_SEG(seg_name) __declspec(code_seg(seg_name))

#define SUSP_ERR(dword) ((DWORD)dword == -1)