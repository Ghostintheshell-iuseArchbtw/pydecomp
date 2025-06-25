// Generated header for amsi.dll
// Generated on: June 24, 2025
// Architecture: x64
// Original file: C:\Windows\System32\amsi.dll

#pragma once
#include <cstring>
#include <cstdlib>
#include <windows.h>
#include <winternl.h>
#include <cstdint>

// Data Structures
typedef struct struct_rbp_data {
    uint8_t padding_0[7];
    uint32_t field_7;
    uint32_t field_7;
    uint32_t field_7;
    uint32_t field_7;
    uint32_t field_7;
    uint32_t field_7;
    uint32_t field_7;
    uint32_t field_7;
} struct_rbp_data_t;

typedef struct struct_rcx_data {
    uint8_t padding_0[4];
    uint32_t field_4;
    uint32_t field_8;
} struct_rcx_data_t;

typedef struct struct_rdx_data {
    uint8_t padding_0[4];
    uint32_t field_4;
    uint32_t field_5;
} struct_rdx_data_t;

typedef struct struct_r8_data {
    uint8_t padding_0[4];
    uint32_t field_4;
    uint32_t field_8;
} struct_r8_data_t;

typedef struct struct_rdi_data {
    uint8_t padding_0[4];
    uint32_t field_4;
    uint32_t field_4;
    uint32_t field_8;
    uint32_t field_8;
} struct_rdi_data_t;

typedef struct struct_rbx_data {
    uint8_t padding_0[8];
    uint32_t field_8;
    uint32_t field_8;
    uint32_t field_8;
} struct_rbx_data_t;

// Function Declarations
extern "C" {
    int AmsiCloseSession(uint64_t param1);
    int AmsiInitialize(uint64_t param1, uint64_t param2);
    int AmsiNotifyOperation(uint64_t param1, uint64_t param2, uint64_t param3, uint64_t param4);
    int AmsiOpenSession(uint64_t param1, uint64_t param2, uint64_t param3);
    int AmsiScanBuffer(uint64_t param1, uint64_t param2, uint64_t param3, uint64_t param4);
    int AmsiScanString(uint64_t param1, uint64_t param2);
    int AmsiUacInitialize(uint64_t param1);
    int AmsiUacScan(uint64_t param1, uint64_t param2, uint64_t param3, uint64_t param4);
    int AmsiUacUninitialize(uint64_t param1, uint64_t param2, uint64_t param3);
    int AmsiUninitialize(uint64_t param1, uint64_t param2, uint64_t param3);
    int DllCanUnloadNow(uint64_t param1);
    int DllGetClassObject(uint64_t param1, uint64_t param2, uint64_t param3);
    int DllRegisterServer(void);
    int DllUnregisterServer(void);
    int sub_1120(uint64_t param1);
    int sub_1140(uint64_t param1);
    int sub_1274(uint64_t param1, uint64_t param2, uint64_t param3, uint64_t param4);
    int sub_12a6(uint64_t param1, uint64_t param2);
    int sub_1408(uint64_t param1, uint64_t param2, uint64_t param3);
    int sub_1411(uint64_t param1, uint64_t param2, uint64_t param3, uint64_t param4);
    int sub_1585(uint64_t param1, uint64_t param2);
    int sub_1748(uint64_t param1, uint64_t param2, uint64_t param3, uint64_t param4);
    int sub_1753(uint64_t param1, uint64_t param2, uint64_t param3, uint64_t param4);
    int sub_1842(uint64_t param1, uint64_t param2, uint64_t param3);
    int sub_18a2(uint64_t param1);
    int sub_1912(uint64_t param1, uint64_t param2, uint64_t param3, uint64_t param4);
    int sub_19ae(uint64_t param1);
    int sub_1bc8(uint64_t param1, uint64_t param2, uint64_t param3);
    int sub_20a0(uint64_t param1, uint64_t param2, uint64_t param3, uint64_t param4);
    int sub_20ae(uint64_t param1, uint64_t param2, uint64_t param3, uint64_t param4);
    int sub_21d8(uint64_t param1, uint64_t param2, uint64_t param3, uint64_t param4);
    int sub_2450(uint64_t param1, uint64_t param2, uint64_t param3);
    int sub_2460(uint64_t param1, uint64_t param2, uint64_t param3, uint64_t param4);
    int sub_24a2(uint64_t param1, uint64_t param2, uint64_t param3, uint64_t param4);
    int sub_2650(uint64_t param1, uint64_t param2);
    int sub_267c(uint64_t param1, uint64_t param2, uint64_t param3);
    int sub_3124(uint64_t param1);
    int sub_31c8(uint64_t param1, uint64_t param2, uint64_t param3, uint64_t param4);
    int sub_3206(uint64_t param1, uint64_t param2, uint64_t param3, uint64_t param4);
    int sub_323b(uint64_t param1, uint64_t param2, uint64_t param3, uint64_t param4);
    int sub_32c0(uint64_t param1, uint64_t param2, uint64_t param3, uint64_t param4);
    int sub_33a8(uint64_t param1, uint64_t param2);
    int sub_3430(uint64_t param1, uint64_t param2, uint64_t param3, uint64_t param4);
    int sub_36de(uint64_t param1, uint64_t param2, uint64_t param3);
    int sub_3818(uint64_t param1);
    int sub_381e(uint64_t param1);
    int sub_3858(uint64_t param1, uint64_t param2, uint64_t param3, uint64_t param4);
    int sub_3866(uint64_t param1, uint64_t param2, uint64_t param3, uint64_t param4);
    int sub_38cc(uint64_t param1, uint64_t param2, uint64_t param3, uint64_t param4);
    int sub_395e(uint64_t param1);
    int sub_39ac(uint64_t param1, uint64_t param2);
    int sub_39b7(uint64_t param1, uint64_t param2);
    int sub_3a0a(uint64_t param1);
    int sub_3a2c(uint64_t param1);
    int sub_3a32(uint64_t param1);
    int sub_3a82(uint64_t param1);
    int sub_3b0c(uint64_t param1, uint64_t param2, uint64_t param3, uint64_t param4);
    int sub_3c51(uint64_t param1, uint64_t param2, uint64_t param3);
    int sub_3cea(uint64_t param1, uint64_t param2, uint64_t param3);
    int sub_3cf6(uint64_t param1, uint64_t param2, uint64_t param3);
    int sub_3d53(uint64_t param1, uint64_t param2);
    int sub_3de4(uint64_t param1);
    int sub_3e68(void);
    int sub_3e98(uint64_t param1);
}

#endif // __AMSI_H__