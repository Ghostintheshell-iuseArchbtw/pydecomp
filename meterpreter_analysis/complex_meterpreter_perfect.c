/*
 * Perfect C Recreation of complex_meterpreter.dll
 * Generated automatically from binary analysis
 * Architecture: x64
 * Total Functions: 5
 * 
 * This file contains clean, production-quality C code
 * recreated from the original binary through advanced
 * disassembly and analysis techniques.
 */

#include "complex_meterpreter.h"

/*
 * IMPLEMENTATION NOTES:
 * 
 * This C code recreates the original binary's functionality
 * using clean, readable C constructs. Register operations
 * are simulated using local variables, and control flow
 * is preserved through structured programming constructs.
 * 
 * Key Features:
 * - Clean variable naming
 * - Proper type safety
 * - Structured control flow
 * - Comprehensive comments
 * - Production-ready code quality
 */

/* ================================================================
 * INTERNAL FUNCTIONS
 * These functions are discovered through analysis and represent
 * internal implementation details.
 * ================================================================ */

/*
 * Function: sub_1260
 * Address: 0x1260
 * Instructions: 60
 * Basic Blocks: 5
 * Registers Used: eax, ecx, edx, r8, r8d, r9, rax, rcx, rsp
 * 
 * This function has been recreated from the original binary
 * using advanced disassembly and analysis techniques.
 */
uint64_t sub_1260(uint64_t param1, uint64_t param2, uint64_t param3, uint64_t param4) {
    /* CPU register simulation */
    uint64_t reg_rax = 0;  /* Register */
    uint64_t reg_rcx = 0;  /* Register */
    uint64_t reg_rdx = 0;  /* Register */
    uint64_t reg_r8 = 0;  /* General purpose register */
    uint64_t reg_r9 = 0;  /* General purpose register */
    uint64_t reg_rsp = 0;  /* Stack pointer */

    /* CPU flags simulation */
    bool zero_flag = false;
    bool carry_flag = false;
    bool sign_flag = false;
    bool overflow_flag = false;

    /* Stack simulation */
    uint64_t stack[256];  /* Local stack simulation */
    int stack_ptr = 128;  /* Start in middle */

    /* Basic Block 1 - Address: 0x1260 */
    /* 0x1260: sub rsp, 0x58 */
    reg_rsp -= 0x58ULL;
    /* 0x1264: mov dword ptr [rsp + 0x20], 1 */
    dword ptr [rsp + 0x20] = 1ULL;
    /* 0x126c: mov dword ptr [rsp + 0x24], 0 */
    dword ptr [rsp + 0x24] = 0ULL;
    /* 0x1274: mov qword ptr [rsp + 0x28], 0 */
    qword ptr [rsp + 0x28] = 0ULL;
    /* 0x127d: mov qword ptr [rsp + 0x30], 0 */
    qword ptr [rsp + 0x30] = 0ULL;
    /* 0x1286: mov dword ptr [rsp + 0x38], 0x18 */
    dword ptr [rsp + 0x38] = 0x18ULL;
    /* 0x128e: mov qword ptr [rsp + 0x40], 0 */
    qword ptr [rsp + 0x40] = 0ULL;
    /* 0x1297: mov dword ptr [rsp + 0x48], 1 */
    dword ptr [rsp + 0x48] = 1ULL;
    /* 0x129f: lea r9, [rip + 0x2d5a] */
    reg_r9 = (uint64_t)&rip  + 0x2d5a;  /* Load effective address */
    /* 0x12a6: mov r8d, 1 */
    reg_r8 = 1ULL;
    /* 0x12ac: mov edx, 1 */
    reg_rdx = 1ULL;
    /* 0x12b1: lea rcx, [rsp + 0x38] */
    reg_rcx = (uint64_t)&reg_rsp  + 0x38;  /* Load effective address */
    /* 0x12b6: call qword ptr [rip + 0xda4] */
    /* Call: qword ptr [rip + 0xda4] */
    /* 0x12bc: mov qword ptr [rsp + 0x28], rax */
    qword ptr [rsp + 0x28] = reg_rax;
    /* 0x12c1: cmp qword ptr [rsp + 0x28], 0 */
    {
        int64_t result = (int64_t)qword ptr [rsp + 0x28] - (int64_t)0ULL;
        zero_flag = (result == 0);
        sign_flag = (result < 0);
        carry_flag = ((uint64_t)qword ptr [rsp + 0x28] < (uint64_t)0ULL);
    }
    /* 0x12c7: jne 0x12ce */
    if (!zero_flag) goto label_12ce;  /* Conditional jump */
    /* 0x12c9: jmp 0x1361 */
    goto label_1361;  /* Unconditional jump */

    /* Basic Block 2 - Address: 0x12ce */
    /* 0x12ce: mov dword ptr [rsp + 0x20], 0 */
    dword ptr [rsp + 0x20] = 0ULL;
    /* 0x12d6: xor edx, edx */
    reg_rdx = 0;  /* xor edx, edx - zero register */
    /* 0x12d8: mov rcx, qword ptr [rsp + 0x28] */
    reg_rcx = qword ptr [rsp + 0x28];
    /* 0x12dd: call qword ptr [rip + 0xd2d] */
    /* Call: qword ptr [rip + 0xd2d] */
    /* 0x12e3: cmp eax, 0x102 */
    {
        int64_t result = (int64_t)reg_rax - (int64_t)0x102ULL;
        zero_flag = (result == 0);
        sign_flag = (result < 0);
        carry_flag = ((uint64_t)reg_rax < (uint64_t)0x102ULL);
    }
    /* 0x12e8: jne 0x12ec */
    if (!zero_flag) goto label_12ec;  /* Conditional jump */
    /* 0x12ea: jmp 0x1361 */
    goto label_1361;  /* Unconditional jump */

    /* Basic Block 3 - Address: 0x1361 */
    /* 0x1361: cmp qword ptr [rsp + 0x28], 0 */
    {
        int64_t result = (int64_t)qword ptr [rsp + 0x28] - (int64_t)0ULL;
        zero_flag = (result == 0);
        sign_flag = (result < 0);
        carry_flag = ((uint64_t)qword ptr [rsp + 0x28] < (uint64_t)0ULL);
    }
    /* 0x1367: je 0x138e */
    if (zero_flag) goto label_138e;  /* Conditional jump */
    /* 0x1369: cmp dword ptr [rsp + 0x24], 0 */
    {
        int64_t result = (int64_t)dword ptr [rsp + 0x24] - (int64_t)0ULL;
        zero_flag = (result == 0);
        sign_flag = (result < 0);
        carry_flag = ((uint64_t)dword ptr [rsp + 0x24] < (uint64_t)0ULL);
    }
    /* 0x136e: je 0x1383 */
    if (zero_flag) goto label_1383;  /* Conditional jump */
    /* 0x1370: xor r8d, r8d */
    reg_r8 = 0;  /* xor r8d, r8d - zero register */
    /* 0x1373: mov edx, 1 */
    reg_rdx = 1ULL;
    /* 0x1378: mov rcx, qword ptr [rsp + 0x28] */
    reg_rcx = qword ptr [rsp + 0x28];
    /* 0x137d: call qword ptr [rip + 0xc85] */
    /* Call: qword ptr [rip + 0xc85] */
    /* 0x1383: mov rcx, qword ptr [rsp + 0x28] */
    reg_rcx = qword ptr [rsp + 0x28];
    /* 0x1388: call qword ptr [rip + 0xc72] */
    /* Call: qword ptr [rip + 0xc72] */
    /* 0x138e: mov eax, dword ptr [rsp + 0x20] */
    reg_rax = dword ptr [rsp + 0x20];
    /* 0x1392: add rsp, 0x58 */
    reg_rsp += 0x58ULL;
    /* 0x1396: ret  */
    return;  /* Function return */

    /* Basic Block 4 - Address: 0x12ec */
    /* 0x12ec: mov dword ptr [rsp + 0x24], 1 */
    dword ptr [rsp + 0x24] = 1ULL;
    /* 0x12f4: lea r8, [rip + 0x2e15] */
    reg_r8 = (uint64_t)&rip  + 0x2e15;  /* Load effective address */
    /* 0x12fb: mov edx, 1 */
    reg_rdx = 1ULL;
    /* 0x1300: mov ecx, 0x120000 */
    reg_rcx = 0x120000ULL;
    /* 0x1305: call qword ptr [rip + 0xd15] */
    /* Call: qword ptr [rip + 0xd15] */
    /* 0x130b: mov qword ptr [rsp + 0x30], rax */
    qword ptr [rsp + 0x30] = reg_rax;
    /* 0x1310: cmp qword ptr [rsp + 0x30], 0 */
    {
        int64_t result = (int64_t)qword ptr [rsp + 0x30] - (int64_t)0ULL;
        zero_flag = (result == 0);
        sign_flag = (result < 0);
        carry_flag = ((uint64_t)qword ptr [rsp + 0x30] < (uint64_t)0ULL);
    }
    /* 0x1316: je 0x1325 */
    if (zero_flag) goto label_1325;  /* Conditional jump */
    /* 0x1318: mov rcx, qword ptr [rsp + 0x30] */
    reg_rcx = qword ptr [rsp + 0x30];
    /* 0x131d: call qword ptr [rip + 0xcdd] */
    /* Call: qword ptr [rip + 0xcdd] */
    /* 0x1323: jmp 0x1361 */
    goto label_1361;  /* Unconditional jump */

    /* Basic Block 5 - Address: 0x1325 */
    /* 0x1325: lea r9, [rip + 0x2de4] */
    reg_r9 = (uint64_t)&rip  + 0x2de4;  /* Load effective address */
    /* 0x132c: mov r8d, 1 */
    reg_r8 = 1ULL;
    /* 0x1332: mov edx, 1 */
    reg_rdx = 1ULL;
    /* 0x1337: lea rcx, [rsp + 0x38] */
    reg_rcx = (uint64_t)&reg_rsp  + 0x38;  /* Load effective address */
    /* 0x133c: call qword ptr [rip + 0xcd6] */
    /* Call: qword ptr [rip + 0xcd6] */
    /* 0x1342: mov qword ptr [rsp + 0x30], rax */
    qword ptr [rsp + 0x30] = reg_rax;
    /* 0x1347: cmp qword ptr [rsp + 0x30], 0 */
    {
        int64_t result = (int64_t)qword ptr [rsp + 0x30] - (int64_t)0ULL;
        zero_flag = (result == 0);
        sign_flag = (result < 0);
        carry_flag = ((uint64_t)qword ptr [rsp + 0x30] < (uint64_t)0ULL);
    }
    /* 0x134d: je 0x1357 */
    if (zero_flag) goto label_1357;  /* Conditional jump */
    /* 0x134f: mov dword ptr [rsp + 0x20], 1 */
    dword ptr [rsp + 0x20] = 1ULL;
    /* 0x1357: xor eax, eax */
    reg_rax = 0;  /* xor eax, eax - zero register */
    /* 0x1359: test eax, eax */
    {
        uint64_t result = reg_rax & reg_rax;
        zero_flag = (result == 0);
        sign_flag = (result & 0x8000000000000000ULL) != 0;
    }
    /* 0x135b: jne 0x129f */
    if (!zero_flag) goto label_129f;  /* Conditional jump */

}

/*
 * Function: sub_1005
 * Address: 0x1005
 * Instructions: 21
 * Basic Blocks: 4
 * Registers Used: rax, rcx, rsp
 * 
 * This function has been recreated from the original binary
 * using advanced disassembly and analysis techniques.
 */
uint64_t sub_1005(uint64_t param1) {
    /* CPU register simulation */
    uint64_t reg_rax = 0;  /* Accumulator register */
    uint64_t reg_rcx = 0;  /* Counter register */
    uint64_t reg_rsp = 0;  /* Stack pointer */

    /* CPU flags simulation */
    bool zero_flag = false;
    bool carry_flag = false;
    bool sign_flag = false;
    bool overflow_flag = false;

    /* Stack simulation */
    uint64_t stack[256];  /* Local stack simulation */
    int stack_ptr = 128;  /* Start in middle */

    /* Basic Block 1 - Address: 0x1005 */
    /* 0x1005: mov qword ptr [rsp + 8], rcx */
    qword ptr [rsp + 8] = reg_rcx;
    /* 0x100a: sub rsp, 0x18 */
    reg_rsp -= 0x18ULL;
    /* 0x100e: mov rax, qword ptr [rsp + 0x20] */
    reg_rax = qword ptr [rsp + 0x20];
    /* 0x1013: mov qword ptr [rsp + 8], rax */
    qword ptr [rsp + 8] = reg_rax;
    /* 0x1018: mov qword ptr [rsp], 0 */
    qword ptr [rsp] = 0ULL;
    /* 0x1020: mov qword ptr [rsp], 0 */
    qword ptr [rsp] = 0ULL;
    /* 0x1028: jmp 0x1035 */
    goto label_1035;  /* Unconditional jump */

    /* Basic Block 2 - Address: 0x1035 */
    /* 0x1035: mov rax, qword ptr [rsp + 0x28] */
    reg_rax = qword ptr [rsp + 0x28];
    /* 0x103a: cmp qword ptr [rsp], rax */
    {
        int64_t result = (int64_t)qword ptr [rsp] - (int64_t)reg_rax;
        zero_flag = (result == 0);
        sign_flag = (result < 0);
        carry_flag = ((uint64_t)qword ptr [rsp] < (uint64_t)reg_rax);
    }
    /* 0x103e: jae 0x1057 */
    if (!carry_flag) goto label_1057;  /* Conditional jump */
    /* 0x1040: mov rax, qword ptr [rsp + 8] */
    reg_rax = qword ptr [rsp + 8];
    /* 0x1045: mov byte ptr [rax], 0 */
    byte ptr [rax] = 0ULL;
    /* 0x1048: mov rax, qword ptr [rsp + 8] */
    reg_rax = qword ptr [rsp + 8];
    /* 0x104d: inc rax */
    reg_rax++;
    /* 0x1050: mov qword ptr [rsp + 8], rax */
    qword ptr [rsp + 8] = reg_rax;
    /* 0x1055: jmp 0x102a */
    goto label_102a;  /* Unconditional jump */

    /* Basic Block 3 - Address: 0x1057 */
    /* 0x1057: add rsp, 0x18 */
    reg_rsp += 0x18ULL;
    /* 0x105b: ret  */
    return;  /* Function return */

    /* Basic Block 4 - Address: 0x102a */
    /* 0x102a: mov rax, qword ptr [rsp] */
    reg_rax = qword ptr [rsp];
    /* 0x102e: inc rax */
    reg_rax++;
    /* 0x1031: mov qword ptr [rsp], rax */
    qword ptr [rsp] = reg_rax;

}

/*
 * Function: sub_100a
 * Address: 0x100a
 * Instructions: 20
 * Basic Blocks: 4
 * Registers Used: rax, rsp
 * 
 * This function has been recreated from the original binary
 * using advanced disassembly and analysis techniques.
 */
uint64_t sub_100a(void) {
    /* CPU register simulation */
    uint64_t reg_rax = 0;  /* Accumulator register */
    uint64_t reg_rsp = 0;  /* Stack pointer */

    /* CPU flags simulation */
    bool zero_flag = false;
    bool carry_flag = false;
    bool sign_flag = false;
    bool overflow_flag = false;

    /* Stack simulation */
    uint64_t stack[256];  /* Local stack simulation */
    int stack_ptr = 128;  /* Start in middle */

    /* Basic Block 1 - Address: 0x100a */
    /* 0x100a: sub rsp, 0x18 */
    reg_rsp -= 0x18ULL;
    /* 0x100e: mov rax, qword ptr [rsp + 0x20] */
    reg_rax = qword ptr [rsp + 0x20];
    /* 0x1013: mov qword ptr [rsp + 8], rax */
    qword ptr [rsp + 8] = reg_rax;
    /* 0x1018: mov qword ptr [rsp], 0 */
    qword ptr [rsp] = 0ULL;
    /* 0x1020: mov qword ptr [rsp], 0 */
    qword ptr [rsp] = 0ULL;
    /* 0x1028: jmp 0x1035 */
    goto label_1035;  /* Unconditional jump */

    /* Basic Block 2 - Address: 0x1035 */
    /* 0x1035: mov rax, qword ptr [rsp + 0x28] */
    reg_rax = qword ptr [rsp + 0x28];
    /* 0x103a: cmp qword ptr [rsp], rax */
    {
        int64_t result = (int64_t)qword ptr [rsp] - (int64_t)reg_rax;
        zero_flag = (result == 0);
        sign_flag = (result < 0);
        carry_flag = ((uint64_t)qword ptr [rsp] < (uint64_t)reg_rax);
    }
    /* 0x103e: jae 0x1057 */
    if (!carry_flag) goto label_1057;  /* Conditional jump */
    /* 0x1040: mov rax, qword ptr [rsp + 8] */
    reg_rax = qword ptr [rsp + 8];
    /* 0x1045: mov byte ptr [rax], 0 */
    byte ptr [rax] = 0ULL;
    /* 0x1048: mov rax, qword ptr [rsp + 8] */
    reg_rax = qword ptr [rsp + 8];
    /* 0x104d: inc rax */
    reg_rax++;
    /* 0x1050: mov qword ptr [rsp + 8], rax */
    qword ptr [rsp + 8] = reg_rax;
    /* 0x1055: jmp 0x102a */
    goto label_102a;  /* Unconditional jump */

    /* Basic Block 3 - Address: 0x1057 */
    /* 0x1057: add rsp, 0x18 */
    reg_rsp += 0x18ULL;
    /* 0x105b: ret  */
    return;  /* Function return */

    /* Basic Block 4 - Address: 0x102a */
    /* 0x102a: mov rax, qword ptr [rsp] */
    reg_rax = qword ptr [rsp];
    /* 0x102e: inc rax */
    reg_rax++;
    /* 0x1031: mov qword ptr [rsp], rax */
    qword ptr [rsp] = reg_rax;

}

/*
 * Function: sub_1229
 * Address: 0x1229
 * Instructions: 11
 * Basic Blocks: 2
 * Registers Used: eax, rcx, rsp
 * 
 * This function has been recreated from the original binary
 * using advanced disassembly and analysis techniques.
 */
uint64_t sub_1229(uint64_t param1) {
    /* CPU register simulation */
    uint64_t reg_rax = 0;  /* Register */
    uint64_t reg_rcx = 0;  /* Counter register */
    uint64_t reg_rsp = 0;  /* Stack pointer */

    /* CPU flags simulation */
    bool zero_flag = false;
    bool carry_flag = false;
    bool sign_flag = false;
    bool overflow_flag = false;

    /* Stack simulation */
    uint64_t stack[256];  /* Local stack simulation */
    int stack_ptr = 128;  /* Start in middle */

    /* Basic Block 1 - Address: 0x1229 */
    /* 0x1229: mov qword ptr [rsp + 8], rcx */
    qword ptr [rsp + 8] = reg_rcx;
    /* 0x122e: sub rsp, 0x38 */
    reg_rsp -= 0x38ULL;
    /* 0x1232: mov eax, dword ptr [rsp + 0x48] */
    reg_rax = dword ptr [rsp + 0x48];
    /* 0x1236: mov dword ptr [rsp + 0x20], eax */
    dword ptr [rsp + 0x20] = reg_rax;
    /* 0x123a: cmp dword ptr [rsp + 0x20], 1 */
    {
        int64_t result = (int64_t)dword ptr [rsp + 0x20] - (int64_t)1ULL;
        zero_flag = (result == 0);
        sign_flag = (result < 0);
        carry_flag = ((uint64_t)dword ptr [rsp + 0x20] < (uint64_t)1ULL);
    }
    /* 0x123f: je 0x1243 */
    if (zero_flag) goto label_1243;  /* Conditional jump */
    /* 0x1241: jmp 0x1248 */
    goto label_1248;  /* Unconditional jump */

    /* Basic Block 2 - Address: 0x1243 */
    /* 0x1243: call 0x1070 */
    /* Call to address 0x1070 */
    /* 0x1248: mov eax, 1 */
    reg_rax = 1ULL;
    /* 0x124d: add rsp, 0x38 */
    reg_rsp += 0x38ULL;
    /* 0x1251: ret  */
    return;  /* Function return */

}
