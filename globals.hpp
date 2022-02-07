#pragma once

inline HINSTANCE g_h_NTDLL;
inline HINSTANCE g_h_KERNEL32;
inline HINSTANCE g_h_current_module;

inline DWORD g_os_version;
inline DWORD g_os_build_number;

#define g_Win8	62
#define g_Win7	61
#define g_Win81	63
#define g_Win10	100
#define g_Win11	100

#define g_Win7_SP1   7601
#define g_Win8_SP1   9600
#define g_Win10_1507 10240
#define g_Win10_1511 10586
#define g_Win10_1607 14393
#define g_Win10_1703 15063
#define g_Win10_1709 16299
#define g_Win10_1803 17134
#define g_Win10_1809 17763
#define g_Win10_1903 18362
#define g_Win10_1909 18363
#define g_Win10_2004 19041
#define g_Win10_20H2 19042
#define g_Win10_21H1 19043
#define g_Win10_21H2 19044
#define g_Win11_21H2 22000