// Generated C++ recreation of complex_meterpreter.dll
// Generated on: June 24, 2025
// Architecture: x64
// Total functions analyzed: 5

#include "complex_meterpreter.h"

// ============ DISCOVERED FUNCTIONS ============

// ============================================
// Complete implementation of sub_122e
// Original Address: 0x122e
// Total Instructions: 10
// Basic Blocks: 2
// Register Usage: eax, rsp
// ============================================
uint64_t sub_122e(void) {
    // CPU Register simulation
    uint64_t reg_rsp = 0;  // Stack pointer
    uint64_t reg_rax = 0;  // Accumulator register

    // CPU Flags simulation
    bool zero_flag = false;
    bool carry_flag = false;
    bool sign_flag = false;
    bool overflow_flag = false;

    // ============= Basic Block 1 =============
    // Address Range: 0x122e - 0x1241
    // Instructions: 6

    // 0x122e: sub rsp, 0x38  [48 83 ec 38]
    reg_rsp -= 56;

    // 0x1232: mov eax, dword ptr [rsp + 0x48]  [8b 44 24 48]
    reg_eax = *(reg_rsp + +72);

    // 0x1236: mov dword ptr [rsp + 0x20], eax  [89 44 24 20]
    *(reg_rsp + +32) = reg_eax;

    // 0x123a: cmp dword ptr [rsp + 0x20], 1  [83 7c 24 20 01]
    // Compare: *(reg_rsp + +32) vs 1

    // 0x123f: je 0x1243  [74 02]
    if (zero_flag) goto label_0x1243;
    // >>> Control flow: Jump to 0x1243

    // 0x1241: jmp 0x1248  [eb 05]
    goto label_0x1248;
    // >>> Control flow: Jump to 0x1248


label_0x1243:
    // ============= Basic Block 2 =============
    // Address Range: 0x1243 - 0x1251
    // Instructions: 4

    // 0x1243: call 0x1070  [e8 28 fe ff ff]
    call_function_0x1070();
    // >>> Function call detected

    // 0x1248: mov eax, 1  [b8 01 00 00 00]
    reg_eax = 1;

    // 0x124d: add rsp, 0x38  [48 83 c4 38]
    reg_rsp += 56;

    // 0x1251: ret   [c3]
    return result;
    // >>> Function return


}

// ============================================
// Complete implementation of sub_1229
// Original Address: 0x1229
// Total Instructions: 11
// Basic Blocks: 2
// Register Usage: eax, rcx, rsp
// ============================================
uint64_t sub_1229(uint64_t param1) {
    // CPU Register simulation
    uint64_t reg_rsp = 0;  // Stack pointer
    uint64_t reg_rax = 0;  // Accumulator register
    uint64_t reg_rcx = 0;  // Counter register

    // CPU Flags simulation
    bool zero_flag = false;
    bool carry_flag = false;
    bool sign_flag = false;
    bool overflow_flag = false;

    // ============= Basic Block 1 =============
    // Address Range: 0x1229 - 0x1241
    // Instructions: 7

    // 0x1229: mov qword ptr [rsp + 8], rcx  [48 89 4c 24 08]
    *(reg_rsp + +8) = reg_rcx;

    // 0x122e: sub rsp, 0x38  [48 83 ec 38]
    reg_rsp -= 56;

    // 0x1232: mov eax, dword ptr [rsp + 0x48]  [8b 44 24 48]
    reg_eax = *(reg_rsp + +72);

    // 0x1236: mov dword ptr [rsp + 0x20], eax  [89 44 24 20]
    *(reg_rsp + +32) = reg_eax;

    // 0x123a: cmp dword ptr [rsp + 0x20], 1  [83 7c 24 20 01]
    // Compare: *(reg_rsp + +32) vs 1

    // 0x123f: je 0x1243  [74 02]
    if (zero_flag) goto label_0x1243;
    // >>> Control flow: Jump to 0x1243

    // 0x1241: jmp 0x1248  [eb 05]
    goto label_0x1248;
    // >>> Control flow: Jump to 0x1248


label_0x1243:
    // ============= Basic Block 2 =============
    // Address Range: 0x1243 - 0x1251
    // Instructions: 4

    // 0x1243: call 0x1070  [e8 28 fe ff ff]
    call_function_0x1070();
    // >>> Function call detected

    // 0x1248: mov eax, 1  [b8 01 00 00 00]
    reg_eax = 1;

    // 0x124d: add rsp, 0x38  [48 83 c4 38]
    reg_rsp += 56;

    // 0x1251: ret   [c3]
    return result;
    // >>> Function return


}

// ============================================
// Complete implementation of sub_100a
// Original Address: 0x100a
// Total Instructions: 20
// Basic Blocks: 4
// Register Usage: rax, rsp
// ============================================
uint64_t sub_100a(void) {
    // CPU Register simulation
    uint64_t reg_rsp = 0;  // Stack pointer
    uint64_t reg_rax = 0;  // Accumulator register

    // CPU Flags simulation
    bool zero_flag = false;
    bool carry_flag = false;
    bool sign_flag = false;
    bool overflow_flag = false;

    // ============= Basic Block 1 =============
    // Address Range: 0x100a - 0x1028
    // Instructions: 6

    // 0x100a: sub rsp, 0x18  [48 83 ec 18]
    reg_rsp -= 24;

    // 0x100e: mov rax, qword ptr [rsp + 0x20]  [48 8b 44 24 20]
    reg_rax = *(reg_rsp + +32);

    // 0x1013: mov qword ptr [rsp + 8], rax  [48 89 44 24 08]
    *(reg_rsp + +8) = reg_rax;

    // 0x1018: mov qword ptr [rsp], 0  [48 c7 04 24 00 00 00 00]
    *(reg_rsp) = 0;

    // 0x1020: mov qword ptr [rsp], 0  [48 c7 04 24 00 00 00 00]
    *(reg_rsp) = 0;

    // 0x1028: jmp 0x1035  [eb 0b]
    goto label_0x1035;
    // >>> Control flow: Jump to 0x1035


label_0x1035:
    // ============= Basic Block 2 =============
    // Address Range: 0x1035 - 0x1055
    // Instructions: 9

    // 0x1035: mov rax, qword ptr [rsp + 0x28]  [48 8b 44 24 28]
    reg_rax = *(reg_rsp + +40);

    // 0x103a: cmp qword ptr [rsp], rax  [48 39 04 24]
    // Compare: *(reg_rsp) vs reg_rax

    // 0x103e: jae 0x1057  [73 17]
    // ASM: jae 0x1057 (Address: 0x103e)
    // >>> Control flow: Jump to 0x1057

    // 0x1040: mov rax, qword ptr [rsp + 8]  [48 8b 44 24 08]
    reg_rax = *(reg_rsp + +8);

    // 0x1045: mov byte ptr [rax], 0  [c6 00 00]
    *(reg_rax) = 0;

    // 0x1048: mov rax, qword ptr [rsp + 8]  [48 8b 44 24 08]
    reg_rax = *(reg_rsp + +8);

    // 0x104d: inc rax  [48 ff c0]
    reg_rax++;

    // 0x1050: mov qword ptr [rsp + 8], rax  [48 89 44 24 08]
    *(reg_rsp + +8) = reg_rax;

    // 0x1055: jmp 0x102a  [eb d3]
    goto label_0x102a;
    // >>> Control flow: Jump to 0x102a


label_0x1057:
    // ============= Basic Block 3 =============
    // Address Range: 0x1057 - 0x105b
    // Instructions: 2

    // 0x1057: add rsp, 0x18  [48 83 c4 18]
    reg_rsp += 24;

    // 0x105b: ret   [c3]
    return result;
    // >>> Function return


label_0x102a:
    // ============= Basic Block 4 =============
    // Address Range: 0x102a - 0x1031
    // Instructions: 3

    // 0x102a: mov rax, qword ptr [rsp]  [48 8b 04 24]
    reg_rax = *(reg_rsp);

    // 0x102e: inc rax  [48 ff c0]
    reg_rax++;

    // 0x1031: mov qword ptr [rsp], rax  [48 89 04 24]
    *(reg_rsp) = reg_rax;


}

// ============================================
// Complete implementation of sub_1005
// Original Address: 0x1005
// Total Instructions: 21
// Basic Blocks: 4
// Register Usage: rax, rcx, rsp
// ============================================
uint64_t sub_1005(uint64_t param1) {
    // CPU Register simulation
    uint64_t reg_rsp = 0;  // Stack pointer
    uint64_t reg_rax = 0;  // Accumulator register
    uint64_t reg_rcx = 0;  // Counter register

    // CPU Flags simulation
    bool zero_flag = false;
    bool carry_flag = false;
    bool sign_flag = false;
    bool overflow_flag = false;

    // ============= Basic Block 1 =============
    // Address Range: 0x1005 - 0x1028
    // Instructions: 7

    // 0x1005: mov qword ptr [rsp + 8], rcx  [48 89 4c 24 08]
    *(reg_rsp + +8) = reg_rcx;

    // 0x100a: sub rsp, 0x18  [48 83 ec 18]
    reg_rsp -= 24;

    // 0x100e: mov rax, qword ptr [rsp + 0x20]  [48 8b 44 24 20]
    reg_rax = *(reg_rsp + +32);

    // 0x1013: mov qword ptr [rsp + 8], rax  [48 89 44 24 08]
    *(reg_rsp + +8) = reg_rax;

    // 0x1018: mov qword ptr [rsp], 0  [48 c7 04 24 00 00 00 00]
    *(reg_rsp) = 0;

    // 0x1020: mov qword ptr [rsp], 0  [48 c7 04 24 00 00 00 00]
    *(reg_rsp) = 0;

    // 0x1028: jmp 0x1035  [eb 0b]
    goto label_0x1035;
    // >>> Control flow: Jump to 0x1035


label_0x1035:
    // ============= Basic Block 2 =============
    // Address Range: 0x1035 - 0x1055
    // Instructions: 9

    // 0x1035: mov rax, qword ptr [rsp + 0x28]  [48 8b 44 24 28]
    reg_rax = *(reg_rsp + +40);

    // 0x103a: cmp qword ptr [rsp], rax  [48 39 04 24]
    // Compare: *(reg_rsp) vs reg_rax

    // 0x103e: jae 0x1057  [73 17]
    // ASM: jae 0x1057 (Address: 0x103e)
    // >>> Control flow: Jump to 0x1057

    // 0x1040: mov rax, qword ptr [rsp + 8]  [48 8b 44 24 08]
    reg_rax = *(reg_rsp + +8);

    // 0x1045: mov byte ptr [rax], 0  [c6 00 00]
    *(reg_rax) = 0;

    // 0x1048: mov rax, qword ptr [rsp + 8]  [48 8b 44 24 08]
    reg_rax = *(reg_rsp + +8);

    // 0x104d: inc rax  [48 ff c0]
    reg_rax++;

    // 0x1050: mov qword ptr [rsp + 8], rax  [48 89 44 24 08]
    *(reg_rsp + +8) = reg_rax;

    // 0x1055: jmp 0x102a  [eb d3]
    goto label_0x102a;
    // >>> Control flow: Jump to 0x102a


label_0x1057:
    // ============= Basic Block 3 =============
    // Address Range: 0x1057 - 0x105b
    // Instructions: 2

    // 0x1057: add rsp, 0x18  [48 83 c4 18]
    reg_rsp += 24;

    // 0x105b: ret   [c3]
    return result;
    // >>> Function return


label_0x102a:
    // ============= Basic Block 4 =============
    // Address Range: 0x102a - 0x1031
    // Instructions: 3

    // 0x102a: mov rax, qword ptr [rsp]  [48 8b 04 24]
    reg_rax = *(reg_rsp);

    // 0x102e: inc rax  [48 ff c0]
    reg_rax++;

    // 0x1031: mov qword ptr [rsp], rax  [48 89 04 24]
    *(reg_rsp) = reg_rax;


}

// ============================================
// Complete implementation of sub_1260
// Original Address: 0x1260
// Total Instructions: 60
// Basic Blocks: 5
// Register Usage: eax, ecx, edx, r8, r8d, r9, rax, rcx, rsp
// ============================================
uint64_t sub_1260(void) {
    // CPU Register simulation
    uint64_t reg_r8d = 0;
    uint64_t reg_r9 = 0;  // General purpose register
    uint64_t reg_r8 = 0;  // General purpose register
    uint64_t reg_rsp = 0;  // Stack pointer
    uint64_t reg_rcx = 0;  // Counter register
    uint64_t reg_rax = 0;  // Accumulator register
    uint64_t reg_rdx = 0;  // Data register

    // CPU Flags simulation
    bool zero_flag = false;
    bool carry_flag = false;
    bool sign_flag = false;
    bool overflow_flag = false;

    // ============= Basic Block 1 =============
    // Address Range: 0x1260 - 0x12c9
    // Instructions: 17

    // 0x1260: sub rsp, 0x58  [48 83 ec 58]
    reg_rsp -= 88;

    // 0x1264: mov dword ptr [rsp + 0x20], 1  [c7 44 24 20 01 00 00 00]
    *(reg_rsp + +32) = 1;

    // 0x126c: mov dword ptr [rsp + 0x24], 0  [c7 44 24 24 00 00 00 00]
    *(reg_rsp + +36) = 0;

    // 0x1274: mov qword ptr [rsp + 0x28], 0  [48 c7 44 24 28 00 00 00]
    *(reg_rsp + +40) = 0;

    // 0x127d: mov qword ptr [rsp + 0x30], 0  [48 c7 44 24 30 00 00 00]
    *(reg_rsp + +48) = 0;

    // 0x1286: mov dword ptr [rsp + 0x38], 0x18  [c7 44 24 38 18 00 00 00]
    *(reg_rsp + +56) = 24;

    // 0x128e: mov qword ptr [rsp + 0x40], 0  [48 c7 44 24 40 00 00 00]
    *(reg_rsp + +64) = 0;

    // 0x1297: mov dword ptr [rsp + 0x48], 1  [c7 44 24 48 01 00 00 00]
    *(reg_rsp + +72) = 1;

    // 0x129f: lea r9, [rip + 0x2d5a]  [4c 8d 0d 5a 2d 00 00]
    reg_r9 = &*(reg_rip + +11610);

    // 0x12a6: mov r8d, 1  [41 b8 01 00 00 00]
    reg_r8d = 1;

    // 0x12ac: mov edx, 1  [ba 01 00 00 00]
    reg_edx = 1;

    // 0x12b1: lea rcx, [rsp + 0x38]  [48 8d 4c 24 38]
    reg_rcx = &*(reg_rsp + +56);

    // 0x12b6: call qword ptr [rip + 0xda4]  [ff 15 a4 0d 00 00]
    // Function call
    // >>> Function call detected

    // 0x12bc: mov qword ptr [rsp + 0x28], rax  [48 89 44 24 28]
    *(reg_rsp + +40) = reg_rax;

    // 0x12c1: cmp qword ptr [rsp + 0x28], 0  [48 83 7c 24 28 00]
    // Compare: *(reg_rsp + +40) vs 0

    // 0x12c7: jne 0x12ce  [75 05]
    if (!zero_flag) goto label_0x12ce;
    // >>> Control flow: Jump to 0x12ce

    // 0x12c9: jmp 0x1361  [e9 93 00 00 00]
    goto label_0x1361;
    // >>> Control flow: Jump to 0x1361


label_0x12ce:
    // ============= Basic Block 2 =============
    // Address Range: 0x12ce - 0x12ea
    // Instructions: 7

    // 0x12ce: mov dword ptr [rsp + 0x20], 0  [c7 44 24 20 00 00 00 00]
    *(reg_rsp + +32) = 0;

    // 0x12d6: xor edx, edx  [33 d2]
    reg_edx ^= reg_edx;

    // 0x12d8: mov rcx, qword ptr [rsp + 0x28]  [48 8b 4c 24 28]
    reg_rcx = *(reg_rsp + +40);

    // 0x12dd: call qword ptr [rip + 0xd2d]  [ff 15 2d 0d 00 00]
    // Function call
    // >>> Function call detected

    // 0x12e3: cmp eax, 0x102  [3d 02 01 00 00]
    // Compare: reg_eax vs 258

    // 0x12e8: jne 0x12ec  [75 02]
    if (!zero_flag) goto label_0x12ec;
    // >>> Control flow: Jump to 0x12ec

    // 0x12ea: jmp 0x1361  [eb 75]
    goto label_0x1361;
    // >>> Control flow: Jump to 0x1361


label_0x1361:
    // ============= Basic Block 3 =============
    // Address Range: 0x1361 - 0x1396
    // Instructions: 13

    // 0x1361: cmp qword ptr [rsp + 0x28], 0  [48 83 7c 24 28 00]
    // Compare: *(reg_rsp + +40) vs 0

    // 0x1367: je 0x138e  [74 25]
    if (zero_flag) goto label_0x138e;
    // >>> Control flow: Jump to 0x138e

    // 0x1369: cmp dword ptr [rsp + 0x24], 0  [83 7c 24 24 00]
    // Compare: *(reg_rsp + +36) vs 0

    // 0x136e: je 0x1383  [74 13]
    if (zero_flag) goto label_0x1383;
    // >>> Control flow: Jump to 0x1383

    // 0x1370: xor r8d, r8d  [45 33 c0]
    reg_r8d ^= reg_r8d;

    // 0x1373: mov edx, 1  [ba 01 00 00 00]
    reg_edx = 1;

    // 0x1378: mov rcx, qword ptr [rsp + 0x28]  [48 8b 4c 24 28]
    reg_rcx = *(reg_rsp + +40);

    // 0x137d: call qword ptr [rip + 0xc85]  [ff 15 85 0c 00 00]
    // Function call
    // >>> Function call detected

    // 0x1383: mov rcx, qword ptr [rsp + 0x28]  [48 8b 4c 24 28]
    reg_rcx = *(reg_rsp + +40);

    // 0x1388: call qword ptr [rip + 0xc72]  [ff 15 72 0c 00 00]
    // Function call
    // >>> Function call detected

    // 0x138e: mov eax, dword ptr [rsp + 0x20]  [8b 44 24 20]
    reg_eax = *(reg_rsp + +32);

    // 0x1392: add rsp, 0x58  [48 83 c4 58]
    reg_rsp += 88;

    // 0x1396: ret   [c3]
    return result;
    // >>> Function return


label_0x12ec:
    // ============= Basic Block 4 =============
    // Address Range: 0x12ec - 0x1323
    // Instructions: 11

    // 0x12ec: mov dword ptr [rsp + 0x24], 1  [c7 44 24 24 01 00 00 00]
    *(reg_rsp + +36) = 1;

    // 0x12f4: lea r8, [rip + 0x2e15]  [4c 8d 05 15 2e 00 00]
    reg_r8 = &*(reg_rip + +11797);

    // 0x12fb: mov edx, 1  [ba 01 00 00 00]
    reg_edx = 1;

    // 0x1300: mov ecx, 0x120000  [b9 00 00 12 00]
    reg_ecx = 1179648;

    // 0x1305: call qword ptr [rip + 0xd15]  [ff 15 15 0d 00 00]
    // Function call
    // >>> Function call detected

    // 0x130b: mov qword ptr [rsp + 0x30], rax  [48 89 44 24 30]
    *(reg_rsp + +48) = reg_rax;

    // 0x1310: cmp qword ptr [rsp + 0x30], 0  [48 83 7c 24 30 00]
    // Compare: *(reg_rsp + +48) vs 0

    // 0x1316: je 0x1325  [74 0d]
    if (zero_flag) goto label_0x1325;
    // >>> Control flow: Jump to 0x1325

    // 0x1318: mov rcx, qword ptr [rsp + 0x30]  [48 8b 4c 24 30]
    reg_rcx = *(reg_rsp + +48);

    // 0x131d: call qword ptr [rip + 0xcdd]  [ff 15 dd 0c 00 00]
    // Function call
    // >>> Function call detected

    // 0x1323: jmp 0x1361  [eb 3c]
    goto label_0x1361;
    // >>> Control flow: Jump to 0x1361


label_0x1325:
    // ============= Basic Block 5 =============
    // Address Range: 0x1325 - 0x135b
    // Instructions: 12

    // 0x1325: lea r9, [rip + 0x2de4]  [4c 8d 0d e4 2d 00 00]
    reg_r9 = &*(reg_rip + +11748);

    // 0x132c: mov r8d, 1  [41 b8 01 00 00 00]
    reg_r8d = 1;

    // 0x1332: mov edx, 1  [ba 01 00 00 00]
    reg_edx = 1;

    // 0x1337: lea rcx, [rsp + 0x38]  [48 8d 4c 24 38]
    reg_rcx = &*(reg_rsp + +56);

    // 0x133c: call qword ptr [rip + 0xcd6]  [ff 15 d6 0c 00 00]
    // Function call
    // >>> Function call detected

    // 0x1342: mov qword ptr [rsp + 0x30], rax  [48 89 44 24 30]
    *(reg_rsp + +48) = reg_rax;

    // 0x1347: cmp qword ptr [rsp + 0x30], 0  [48 83 7c 24 30 00]
    // Compare: *(reg_rsp + +48) vs 0

    // 0x134d: je 0x1357  [74 08]
    if (zero_flag) goto label_0x1357;
    // >>> Control flow: Jump to 0x1357

    // 0x134f: mov dword ptr [rsp + 0x20], 1  [c7 44 24 20 01 00 00 00]
    *(reg_rsp + +32) = 1;

    // 0x1357: xor eax, eax  [33 c0]
    reg_eax ^= reg_eax;

    // 0x1359: test eax, eax  [85 c0]
    // Test: reg_eax & reg_eax

    // 0x135b: jne 0x129f  [0f 85 3e ff ff ff]
    if (!zero_flag) goto label_0x129f;
    // >>> Control flow: Jump to 0x129f


}
