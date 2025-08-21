// Generated header for complex_meterpreter.dll
// Generated on: June 24, 2025
// Architecture: x64
// Original file: /home/alice/Desktop/pydecomp/test_binaries/complex_meterpreter.dll

#pragma once
#include <windows.h>
#include <processthreadsapi.h>
#include <cstdint>
#include <fileapi.h>
#include <cstdlib>
#include <cstring>

// Data Structures
typedef struct struct_rsp_data {
    uint8_t padding_0[32];
    uint32_t field_20;
    uint32_t field_20;
    uint32_t field_20;
    uint32_t field_20;
    uint32_t field_24;
    uint32_t field_24;
    uint32_t field_24;
    uint32_t field_28;
    uint32_t field_28;
    uint32_t field_28;
    uint32_t field_28;
    uint32_t field_28;
    uint32_t field_28;
    uint32_t field_28;
    uint8_t padding_2c[4];
    uint32_t field_30;
    uint32_t field_30;
    uint32_t field_30;
    uint32_t field_30;
    uint32_t field_30;
    uint32_t field_30;
    uint8_t padding_34[4];
    uint32_t field_38;
    uint32_t field_38;
    uint32_t field_38;
    uint8_t padding_3c[4];
    uint32_t field_40;
    uint8_t padding_44[4];
    uint32_t field_48;
} struct_rsp_data_t;

typedef struct struct_rip_data {
    uint8_t padding_0[3186];
    uint32_t field_c72;
    uint8_t padding_c76[15];
    uint32_t field_c85;
    uint8_t padding_c89[77];
    uint32_t field_cd6;
    uint8_t padding_cda[3];
    uint32_t field_cdd;
    uint8_t padding_ce1[52];
    uint32_t field_d15;
    uint8_t padding_d19[20];
    uint32_t field_d2d;
    uint8_t padding_d31[115];
    uint32_t field_da4;
    uint8_t padding_da8[8114];
    uint32_t field_2d5a;
    uint8_t padding_2d5e[134];
    uint32_t field_2de4;
    uint8_t padding_2de8[45];
    uint32_t field_2e15;
} struct_rip_data_t;

// Function Declarations
extern "C" {
    int sub_1005(uint64_t param1);
    int sub_100a(void);
    int sub_1229(uint64_t param1);
    int sub_122e(void);
    uint32_t sub_1260(uint64_t param1, uint64_t param2, uint64_t param3);
}

#endif // __COMPLEX_METERPRETER_H__