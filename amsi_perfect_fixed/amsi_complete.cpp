// Generated C++ recreation of amsi.dll
// Generated on: June 24, 2025
// Architecture: x64
// Total functions analyzed: 64

#include "amsi.h"

// ============ EXPORTED FUNCTIONS ============

// ============================================
// Complete implementation of DllRegisterServer
// Original Address: 0xa710
// Total Instructions: 2
// Basic Blocks: 1
// Register Usage: eax
// ============================================
uint64_t DllRegisterServer(void) {
    // CPU Register simulation
    uint64_t reg_rax = 0;  // Accumulator register

    // CPU Flags simulation
    bool zero_flag = false;
    bool carry_flag = false;
    bool sign_flag = false;
    bool overflow_flag = false;

    // ============= Basic Block 1 =============
    // Address Range: 0xa710 - 0xa715
    // Instructions: 2

    // 0xa710: mov eax, 80070032h  [b8 32 00 07 80]
    reg_eax = 2147942450;

    // 0xa715: ret   [c3]
    return result;
    // >>> Function return


}

// ============================================
// Complete implementation of DllUnregisterServer
// Original Address: 0xa710
// Total Instructions: 2
// Basic Blocks: 1
// Register Usage: eax
// ============================================
uint64_t DllUnregisterServer(void) {
    // CPU Register simulation
    uint64_t reg_rax = 0;  // Accumulator register

    // CPU Flags simulation
    bool zero_flag = false;
    bool carry_flag = false;
    bool sign_flag = false;
    bool overflow_flag = false;

    // ============= Basic Block 1 =============
    // Address Range: 0xa710 - 0xa715
    // Instructions: 2

    // 0xa710: mov eax, 80070032h  [b8 32 00 07 80]
    reg_eax = 2147942450;

    // 0xa715: ret   [c3]
    return result;
    // >>> Function return


}

// ============================================
// Complete implementation of AmsiCloseSession
// Original Address: 0x8af0
// Total Instructions: 4
// Basic Blocks: 1
// Register Usage: rax, rcx
// ============================================
void AmsiCloseSession(void) {
    // CPU Register simulation
    uint64_t reg_rcx = 0;  // Counter register
    uint64_t reg_rax = 0;  // Accumulator register

    // CPU Flags simulation
    bool zero_flag = false;
    bool carry_flag = false;
    bool sign_flag = false;
    bool overflow_flag = false;

    // ============= Basic Block 1 =============
    // Address Range: 0x8af0 - 0x8afb
    // Instructions: 4

    // 0x8af0: mov rcx, qword ptr [rcx + 10h]  [48 8b 49 10]
    reg_rcx = unknown_operand;

    // 0x8af4: mov rax, qword ptr [rcx]  [48 8b 01]
    reg_rax = unknown_operand;

    // 0x8af7: mov rax, qword ptr [rax + 20h]  [48 8b 40 20]
    reg_rax = unknown_operand;

    // 0x8afb: jmp 0e010h  [e9 10 55 00 00]
    goto label_0xe010;
    // >>> Control flow: Jump to 0xe010


}

// ============================================
// Complete implementation of DllCanUnloadNow
// Original Address: 0x8d30
// Total Instructions: 11
// Basic Blocks: 1
// Register Usage: cl, eax, ecx, rax, rcx, rsp
// ============================================
uint64_t DllCanUnloadNow(void) {
    // CPU Register simulation
    uint64_t reg_rcx = 0;  // Counter register
    uint64_t reg_rax = 0;  // Accumulator register
    uint64_t reg_rsp = 0;  // Stack pointer

    // CPU Flags simulation
    bool zero_flag = false;
    bool carry_flag = false;
    bool sign_flag = false;
    bool overflow_flag = false;

    // ============= Basic Block 1 =============
    // Address Range: 0x8d30 - 0x8d58
    // Instructions: 11

    // 0x8d30: sub rsp, 28h  [48 83 ec 28]
    reg_rsp -= 40;

    // 0x8d34: mov rax, qword ptr [rip + 0e0d5h]  [48 8b 05 d5 e0 00 00]
    reg_rax = unknown_operand;

    // 0x8d3b: lea rcx, [rip + 0e0ceh]  [48 8d 0d ce e0 00 00]
    reg_rcx = &unknown_operand;

    // 0x8d42: mov rax, qword ptr [rax + 18h]  [48 8b 40 18]
    reg_rax = unknown_operand;

    // 0x8d46: call 0e010h  [e8 c5 52 00 00]
    call_function_0xe010();
    // >>> Function call detected

    // 0x8d4b: xor ecx, ecx  [33 c9]
    reg_ecx ^= reg_ecx;

    // 0x8d4d: test eax, eax  [85 c0]
    // Test: reg_eax & reg_eax

    // 0x8d4f: setne cl  [0f 95 c1]
    // ASM: setne cl (Address: 0x8d4f)

    // 0x8d52: mov eax, ecx  [8b c1]
    reg_eax = reg_ecx;

    // 0x8d54: add rsp, 28h  [48 83 c4 28]
    reg_rsp += 40;

    // 0x8d58: ret   [c3]
    return result;
    // >>> Function return


}

// ============================================
// Complete implementation of AmsiOpenSession
// Original Address: 0x8a90
// Total Instructions: 25
// Basic Blocks: 3
// Register Usage: eax, r8d, rax, rcx, rdx
// ============================================
uint64_t AmsiOpenSession(uint64_t param1, uint64_t param2) {
    // CPU Register simulation
    uint64_t reg_rcx = 0;  // Counter register
    uint64_t reg_rax = 0;  // Accumulator register
    uint64_t reg_r8d = 0;
    uint64_t reg_rdx = 0;  // Data register

    // CPU Flags simulation
    bool zero_flag = false;
    bool carry_flag = false;
    bool sign_flag = false;
    bool overflow_flag = false;

    // ============= Basic Block 1 =============
    // Address Range: 0x8a90 - 0x8aa6
    // Instructions: 8

    // 0x8a90: test rdx, rdx  [48 85 d2]
    // Test: reg_rdx & reg_rdx

    // 0x8a93: je 8aa1h  [74 0c]
    if (zero_flag) goto label_0x8aa1;
    // >>> Control flow: Jump to 0x8aa1

    // 0x8a95: test rcx, rcx  [48 85 c9]
    // Test: reg_rcx & reg_rcx

    // 0x8a98: je 8aa1h  [74 07]
    if (zero_flag) goto label_0x8aa1;
    // >>> Control flow: Jump to 0x8aa1

    // 0x8a9a: cmp qword ptr [rcx + 8], 0  [48 83 79 08 00]
    // Compare: unknown_operand vs 0

    // 0x8a9f: jne 8aa8h  [75 07]
    if (!zero_flag) goto label_0x8aa8;
    // >>> Control flow: Jump to 0x8aa8

    // 0x8aa1: mov eax, 80070057h  [b8 57 00 07 80]
    reg_eax = 2147942487;

    // 0x8aa6: ret   [c3]
    return result;
    // >>> Function return


label_0x8aa8:
    // ============= Basic Block 2 =============
    // Address Range: 0x8aa8 - 0x8ac9
    // Instructions: 11

    // 0x8aa8: cmp qword ptr [rcx + 10h], 0  [48 83 79 10 00]
    // Compare: unknown_operand vs 0

    // 0x8aad: je 8aa1h  [74 f2]
    if (zero_flag) goto label_0x8aa1;
    // >>> Control flow: Jump to 0x8aa1

    // 0x8aaf: mov r8d, 1  [41 b8 01 00 00 00]
    reg_r8d = 1;

    // 0x8ab5: mov eax, r8d  [41 8b c0]
    reg_eax = reg_r8d;

    // 0x8ab8: lock xadd dword ptr [rcx + 18h], eax  [f0 0f c1 41 18]
    // ASM: lock xadd dword ptr [rcx + 18h], eax (Address: 0x8ab8)

    // 0x8abd: add eax, r8d  [41 03 c0]
    reg_eax += reg_r8d;

    // 0x8ac0: cdqe   [48 98]
    // ASM: cdqe  (Address: 0x8ac0)

    // 0x8ac2: mov qword ptr [rdx], rax  [48 89 02]
    unknown_operand = reg_rax;

    // 0x8ac5: je 8acbh  [74 04]
    if (zero_flag) goto label_0x8acb;
    // >>> Control flow: Jump to 0x8acb

    // 0x8ac7: xor eax, eax  [33 c0]
    reg_eax ^= reg_eax;

    // 0x8ac9: ret   [c3]
    return result;
    // >>> Function return


label_0x8acb:
    // ============= Basic Block 3 =============
    // Address Range: 0x8acb - 0x8adb
    // Instructions: 6

    // 0x8acb: mov eax, r8d  [41 8b c0]
    reg_eax = reg_r8d;

    // 0x8ace: lock xadd dword ptr [rcx + 18h], eax  [f0 0f c1 41 18]
    // ASM: lock xadd dword ptr [rcx + 18h], eax (Address: 0x8ace)

    // 0x8ad3: add eax, r8d  [41 03 c0]
    reg_eax += reg_r8d;

    // 0x8ad6: cdqe   [48 98]
    // ASM: cdqe  (Address: 0x8ad6)

    // 0x8ad8: mov qword ptr [rdx], rax  [48 89 02]
    unknown_operand = reg_rax;

    // 0x8adb: jmp 8ac7h  [eb ea]
    goto label_0x8ac7;
    // >>> Control flow: Jump to 0x8ac7


}

// ============================================
// Complete implementation of AmsiUacUninitialize
// Original Address: 0xb6c0
// Total Instructions: 21
// Basic Blocks: 1
// Register Usage: edx, r8, r9, rax, rbx, rcx, rsp
// ============================================
uint64_t AmsiUacUninitialize(uint64_t param1) {
    // CPU Register simulation
    uint64_t reg_rdx = 0;  // Data register
    uint64_t reg_rsp = 0;  // Stack pointer
    uint64_t reg_rax = 0;  // Accumulator register
    uint64_t reg_r9 = 0;  // General purpose register
    uint64_t reg_rbx = 0;  // Base register
    uint64_t reg_rcx = 0;  // Counter register
    uint64_t reg_r8 = 0;  // General purpose register

    // CPU Flags simulation
    bool zero_flag = false;
    bool carry_flag = false;
    bool sign_flag = false;
    bool overflow_flag = false;

    // ============= Basic Block 1 =============
    // Address Range: 0xb6c0 - 0xb70c
    // Instructions: 21

    // 0xb6c0: push rbx  [40 53]
    // PUSH reg_rbx

    // 0xb6c2: sub rsp, 20h  [48 83 ec 20]
    reg_rsp -= 32;

    // 0xb6c6: mov rbx, rcx  [48 8b d9]
    reg_rbx = reg_rcx;

    // 0xb6c9: mov rcx, qword ptr [rip + 0a978h]  [48 8b 0d 78 a9 00 00]
    reg_rcx = unknown_operand;

    // 0xb6d0: lea rax, [rip + 0a971h]  [48 8d 05 71 a9 00 00]
    reg_rax = &unknown_operand;

    // 0xb6d7: cmp rcx, rax  [48 3b c8]
    // Compare: reg_rcx vs reg_rax

    // 0xb6da: je 0b6fah  [74 1e]
    if (zero_flag) goto label_0xb6fa;
    // >>> Control flow: Jump to 0xb6fa

    // 0xb6dc: test byte ptr [rcx + 1ch], 4  [f6 41 1c 04]
    // Test: unknown_operand & 4

    // 0xb6e0: je 0b6fah  [74 18]
    if (zero_flag) goto label_0xb6fa;
    // >>> Control flow: Jump to 0xb6fa

    // 0xb6e2: mov rcx, qword ptr [rcx + 10h]  [48 8b 49 10]
    reg_rcx = unknown_operand;

    // 0xb6e6: lea r8, [rip + 50c3h]  [4c 8d 05 c3 50 00 00]
    reg_r8 = &unknown_operand;

    // 0xb6ed: mov edx, 20h  [ba 20 00 00 00]
    reg_edx = 32;

    // 0xb6f2: mov r9, rbx  [4c 8b cb]
    reg_r9 = reg_rbx;

    // 0xb6f5: call 0b848h  [e8 4e 01 00 00]
    call_function_0xb848();
    // >>> Function call detected

    // 0xb6fa: test rbx, rbx  [48 85 db]
    // Test: reg_rbx & reg_rbx

    // 0xb6fd: je 0b707h  [74 08]
    if (zero_flag) goto label_0xb707;
    // >>> Control flow: Jump to 0xb707

    // 0xb6ff: mov rcx, rbx  [48 8b cb]
    reg_rcx = reg_rbx;

    // 0xb702: call 18a0h  [e8 99 61 ff ff]
    call_function_0x18a0();
    // >>> Function call detected

    // 0xb707: add rsp, 20h  [48 83 c4 20]
    reg_rsp += 32;

    // 0xb70b: pop rbx  [5b]
    // POP reg_rbx

    // 0xb70c: ret   [c3]
    return result;
    // >>> Function return


}

// ============================================
// Complete implementation of AmsiScanString
// Original Address: 0x8140
// Total Instructions: 24
// Basic Blocks: 2
// Register Usage: eax, r10, r11, r11d, r11w, r8, r9, rax, rdx, rsp
// ============================================
uint64_t AmsiScanString(uint64_t param2, uint64_t param3) {
    // CPU Register simulation
    uint64_t reg_r11 = 0;  // General purpose register
    uint64_t reg_rdx = 0;  // Data register
    uint64_t reg_rsp = 0;  // Stack pointer
    uint64_t reg_rax = 0;  // Accumulator register
    uint64_t reg_r9 = 0;  // General purpose register
    uint64_t reg_r11w = 0;
    uint64_t reg_r10 = 0;  // General purpose register
    uint64_t reg_r8 = 0;  // General purpose register
    uint64_t reg_r11d = 0;

    // CPU Flags simulation
    bool zero_flag = false;
    bool carry_flag = false;
    bool sign_flag = false;
    bool overflow_flag = false;

    // ============= Basic Block 1 =============
    // Address Range: 0x8140 - 0x817e
    // Instructions: 19

    // 0x8140: sub rsp, 38h  [48 83 ec 38]
    reg_rsp -= 56;

    // 0x8144: xor r11d, r11d  [45 33 db]
    reg_r11d ^= reg_r11d;

    // 0x8147: mov r10, r8  [4d 8b d0]
    reg_r10 = reg_r8;

    // 0x814a: test rdx, rdx  [48 85 d2]
    // Test: reg_rdx & reg_rdx

    // 0x814d: je 8175h  [74 26]
    if (zero_flag) goto label_0x8175;
    // >>> Control flow: Jump to 0x8175

    // 0x814f: mov rax, qword ptr [rsp + 60h]  [48 8b 44 24 60]
    reg_rax = unknown_operand;

    // 0x8154: test rax, rax  [48 85 c0]
    // Test: reg_rax & reg_rax

    // 0x8157: je 8175h  [74 1c]
    if (zero_flag) goto label_0x8175;
    // >>> Control flow: Jump to 0x8175

    // 0x8159: or r8, 0ffffffffffffffffh  [49 83 c8 ff]
    reg_r8 |= -1;

    // 0x815d: inc r8  [49 ff c0]
    reg_r8++;

    // 0x8160: cmp word ptr [rdx + r8*2], r11w  [66 46 39 1c 42]
    // Compare: unknown_operand vs reg_r11w

    // 0x8165: jne 815dh  [75 f6]
    if (!zero_flag) goto label_0x815d;
    // >>> Control flow: Jump to 0x815d

    // 0x8167: add r8, r8  [4d 03 c0]
    reg_r8 += reg_r8;

    // 0x816a: mov r11d, 0ffffffffh  [41 bb ff ff ff ff]
    reg_r11d = 4294967295;

    // 0x8170: cmp r8, r11  [4d 3b c3]
    // Compare: reg_r8 vs reg_r11

    // 0x8173: jbe 8180h  [76 0b]
    // ASM: jbe 8180h (Address: 0x8173)
    // >>> Control flow: Jump to 0x8180

    // 0x8175: mov eax, 80070057h  [b8 57 00 07 80]
    reg_eax = 2147942487;

    // 0x817a: add rsp, 38h  [48 83 c4 38]
    reg_rsp += 56;

    // 0x817e: ret   [c3]
    return result;
    // >>> Function return


label_0x8180:
    // ============= Basic Block 2 =============
    // Address Range: 0x8180 - 0x8192
    // Instructions: 5

    // 0x8180: mov qword ptr [rsp + 28h], rax  [48 89 44 24 28]
    unknown_operand = reg_rax;

    // 0x8185: mov qword ptr [rsp + 20h], r9  [4c 89 4c 24 20]
    unknown_operand = reg_r9;

    // 0x818a: mov r9, r10  [4d 8b ca]
    reg_r9 = reg_r10;

    // 0x818d: call 81a0h  [e8 0e 00 00 00]
    call_function_0x81a0();
    // >>> Function call detected

    // 0x8192: jmp 817ah  [eb e6]
    goto label_0x817a;
    // >>> Control flow: Jump to 0x817a


}

// ============================================
// Complete implementation of AmsiUninitialize
// Original Address: 0x1840
// Total Instructions: 22
// Basic Blocks: 2
// Register Usage: edx, r8, r9, rax, rbx, rcx, rsp
// ============================================
uint64_t AmsiUninitialize(uint64_t param1) {
    // CPU Register simulation
    uint64_t reg_rdx = 0;  // Data register
    uint64_t reg_rsp = 0;  // Stack pointer
    uint64_t reg_rax = 0;  // Accumulator register
    uint64_t reg_r9 = 0;  // General purpose register
    uint64_t reg_rbx = 0;  // Base register
    uint64_t reg_rcx = 0;  // Counter register
    uint64_t reg_r8 = 0;  // General purpose register

    // CPU Flags simulation
    bool zero_flag = false;
    bool carry_flag = false;
    bool sign_flag = false;
    bool overflow_flag = false;

    // ============= Basic Block 1 =============
    // Address Range: 0x1840 - 0x1874
    // Instructions: 16

    // 0x1840: push rbx  [40 53]
    // PUSH reg_rbx

    // 0x1842: sub rsp, 20h  [48 83 ec 20]
    reg_rsp -= 32;

    // 0x1846: mov rbx, rcx  [48 8b d9]
    reg_rbx = reg_rcx;

    // 0x1849: mov rcx, qword ptr [rip + 147f8h]  [48 8b 0d f8 47 01 00]
    reg_rcx = unknown_operand;

    // 0x1850: lea rax, [rip + 147f1h]  [48 8d 05 f1 47 01 00]
    reg_rax = &unknown_operand;

    // 0x1857: cmp rcx, rax  [48 3b c8]
    // Compare: reg_rcx vs reg_rax

    // 0x185a: je 1862h  [74 06]
    if (zero_flag) goto label_0x1862;
    // >>> Control flow: Jump to 0x1862

    // 0x185c: test byte ptr [rcx + 1ch], 4  [f6 41 1c 04]
    // Test: unknown_operand & 4

    // 0x1860: jne 1876h  [75 14]
    if (!zero_flag) goto label_0x1876;
    // >>> Control flow: Jump to 0x1876

    // 0x1862: test rbx, rbx  [48 85 db]
    // Test: reg_rbx & reg_rbx

    // 0x1865: je 186fh  [74 08]
    if (zero_flag) goto label_0x186f;
    // >>> Control flow: Jump to 0x186f

    // 0x1867: mov rcx, rbx  [48 8b cb]
    reg_rcx = reg_rbx;

    // 0x186a: call 18a0h  [e8 31 00 00 00]
    call_function_0x18a0();
    // >>> Function call detected

    // 0x186f: add rsp, 20h  [48 83 c4 20]
    reg_rsp += 32;

    // 0x1873: pop rbx  [5b]
    // POP reg_rbx

    // 0x1874: ret   [c3]
    return result;
    // >>> Function return


label_0x1876:
    // ============= Basic Block 2 =============
    // Address Range: 0x1876 - 0x188e
    // Instructions: 6

    // 0x1876: mov rcx, qword ptr [rcx + 10h]  [48 8b 49 10]
    reg_rcx = unknown_operand;

    // 0x187a: lea r8, [rip + 0ef2fh]  [4c 8d 05 2f ef 00 00]
    reg_r8 = &unknown_operand;

    // 0x1881: mov edx, 17h  [ba 17 00 00 00]
    reg_edx = 23;

    // 0x1886: mov r9, rbx  [4c 8b cb]
    reg_r9 = reg_rbx;

    // 0x1889: call 0b848h  [e8 ba 9f 00 00]
    call_function_0xb848();
    // >>> Function call detected

    // 0x188e: jmp 1862h  [eb d2]
    goto label_0x1862;
    // >>> Control flow: Jump to 0x1862


}

// ============================================
// Complete implementation of AmsiNotifyOperation
// Original Address: 0x8b60
// Total Instructions: 56
// Basic Blocks: 3
// Register Usage: eax, edi, r14, r8d, r9, rax, rbp, rbx, rcx, rdi, rdx, rsi, rsp
// ============================================
uint64_t AmsiNotifyOperation(uint64_t param2, uint64_t param4) {
    // CPU Register simulation
    uint64_t reg_rdx = 0;  // Data register
    uint64_t reg_rbp = 0;  // Base pointer
    uint64_t reg_rsp = 0;  // Stack pointer
    uint64_t reg_rax = 0;  // Accumulator register
    uint64_t reg_rsi = 0;  // Source index
    uint64_t reg_r14 = 0;  // General purpose register
    uint64_t reg_r9 = 0;  // General purpose register
    uint64_t reg_rdi = 0;  // Destination index
    uint64_t reg_rbx = 0;  // Base register
    uint64_t reg_rcx = 0;  // Counter register
    uint64_t reg_r8d = 0;

    // CPU Flags simulation
    bool zero_flag = false;
    bool carry_flag = false;
    bool sign_flag = false;
    bool overflow_flag = false;

    // ============= Basic Block 1 =============
    // Address Range: 0x8b60 - 0x8bc7
    // Instructions: 28

    // 0x8b60: mov rax, rsp  [48 8b c4]
    reg_rax = reg_rsp;

    // 0x8b63: mov qword ptr [rax + 8], rbx  [48 89 58 08]
    unknown_operand = reg_rbx;

    // 0x8b67: mov qword ptr [rax + 10h], rbp  [48 89 68 10]
    unknown_operand = reg_rbp;

    // 0x8b6b: mov qword ptr [rax + 18h], rsi  [48 89 70 18]
    unknown_operand = reg_rsi;

    // 0x8b6f: mov qword ptr [rax + 20h], rdi  [48 89 78 20]
    unknown_operand = reg_rdi;

    // 0x8b73: push r14  [41 56]
    // PUSH reg_r14

    // 0x8b75: sub rsp, 40h  [48 83 ec 40]
    reg_rsp -= 64;

    // 0x8b79: mov r14, r9  [4d 8b f1]
    reg_r14 = reg_r9;

    // 0x8b7c: mov edi, r8d  [41 8b f8]
    reg_edi = reg_r8d;

    // 0x8b7f: mov rsi, rdx  [48 8b f2]
    reg_rsi = reg_rdx;

    // 0x8b82: mov rbx, rcx  [48 8b d9]
    reg_rbx = reg_rcx;

    // 0x8b85: mov rcx, qword ptr [rip + 0d4bch]  [48 8b 0d bc d4 00 00]
    reg_rcx = unknown_operand;

    // 0x8b8c: lea rax, [rip + 0d4b5h]  [48 8d 05 b5 d4 00 00]
    reg_rax = &unknown_operand;

    // 0x8b93: mov rbp, qword ptr [rsp + 70h]  [48 8b 6c 24 70]
    reg_rbp = unknown_operand;

    // 0x8b98: cmp rcx, rax  [48 3b c8]
    // Compare: reg_rcx vs reg_rax

    // 0x8b9b: je 8ba3h  [74 06]
    if (zero_flag) goto label_0x8ba3;
    // >>> Control flow: Jump to 0x8ba3

    // 0x8b9d: test byte ptr [rcx + 1ch], 4  [f6 41 1c 04]
    // Test: unknown_operand & 4

    // 0x8ba1: jne 8c0ah  [75 67]
    if (!zero_flag) goto label_0x8c0a;
    // >>> Control flow: Jump to 0x8c0a

    // 0x8ba3: test rsi, rsi  [48 85 f6]
    // Test: reg_rsi & reg_rsi

    // 0x8ba6: jne 8bc9h  [75 21]
    if (!zero_flag) goto label_0x8bc9;
    // >>> Control flow: Jump to 0x8bc9

    // 0x8ba8: mov eax, 80070057h  [b8 57 00 07 80]
    reg_eax = 2147942487;

    // 0x8bad: mov rbx, qword ptr [rsp + 50h]  [48 8b 5c 24 50]
    reg_rbx = unknown_operand;

    // 0x8bb2: mov rbp, qword ptr [rsp + 58h]  [48 8b 6c 24 58]
    reg_rbp = unknown_operand;

    // 0x8bb7: mov rsi, qword ptr [rsp + 60h]  [48 8b 74 24 60]
    reg_rsi = unknown_operand;

    // 0x8bbc: mov rdi, qword ptr [rsp + 68h]  [48 8b 7c 24 68]
    reg_rdi = unknown_operand;

    // 0x8bc1: add rsp, 40h  [48 83 c4 40]
    reg_rsp += 64;

    // 0x8bc5: pop r14  [41 5e]
    // POP reg_r14

    // 0x8bc7: ret   [c3]
    return result;
    // >>> Function return


label_0x8c0a:
    // ============= Basic Block 2 =============
    // Address Range: 0x8c0a - 0x8c24
    // Instructions: 7

    // 0x8c0a: mov rcx, qword ptr [rcx + 10h]  [48 8b 49 10]
    reg_rcx = unknown_operand;

    // 0x8c0e: mov r9, rbx  [4c 8b cb]
    reg_r9 = reg_rbx;

    // 0x8c11: mov qword ptr [rsp + 30h], rbp  [48 89 6c 24 30]
    unknown_operand = reg_rbp;

    // 0x8c16: mov dword ptr [rsp + 28h], edi  [89 7c 24 28]
    unknown_operand = reg_edi;

    // 0x8c1a: mov qword ptr [rsp + 20h], rsi  [48 89 74 24 20]
    unknown_operand = reg_rsi;

    // 0x8c1f: call 0b8f4h  [e8 d0 2c 00 00]
    call_function_0xb8f4();
    // >>> Function call detected

    // 0x8c24: jmp 8ba3h  [e9 7a ff ff ff]
    goto label_0x8ba3;
    // >>> Control flow: Jump to 0x8ba3


label_0x8bc9:
    // ============= Basic Block 3 =============
    // Address Range: 0x8bc9 - 0x8c08
    // Instructions: 21

    // 0x8bc9: test edi, edi  [85 ff]
    // Test: reg_edi & reg_edi

    // 0x8bcb: je 8ba8h  [74 db]
    if (zero_flag) goto label_0x8ba8;
    // >>> Control flow: Jump to 0x8ba8

    // 0x8bcd: test rbp, rbp  [48 85 ed]
    // Test: reg_rbp & reg_rbp

    // 0x8bd0: je 8ba8h  [74 d6]
    if (zero_flag) goto label_0x8ba8;
    // >>> Control flow: Jump to 0x8ba8

    // 0x8bd2: test rbx, rbx  [48 85 db]
    // Test: reg_rbx & reg_rbx

    // 0x8bd5: je 8ba8h  [74 d1]
    if (zero_flag) goto label_0x8ba8;
    // >>> Control flow: Jump to 0x8ba8

    // 0x8bd7: mov rdx, qword ptr [rbx + 8]  [48 8b 53 08]
    reg_rdx = unknown_operand;

    // 0x8bdb: test rdx, rdx  [48 85 d2]
    // Test: reg_rdx & reg_rdx

    // 0x8bde: je 8ba8h  [74 c8]
    if (zero_flag) goto label_0x8ba8;
    // >>> Control flow: Jump to 0x8ba8

    // 0x8be0: mov rcx, qword ptr [rbx + 10h]  [48 8b 4b 10]
    reg_rcx = unknown_operand;

    // 0x8be4: test rcx, rcx  [48 85 c9]
    // Test: reg_rcx & reg_rcx

    // 0x8be7: je 8ba8h  [74 bf]
    if (zero_flag) goto label_0x8ba8;
    // >>> Control flow: Jump to 0x8ba8

    // 0x8be9: mov rax, qword ptr [rcx]  [48 8b 01]
    reg_rax = unknown_operand;

    // 0x8bec: mov r9, r14  [4d 8b ce]
    reg_r9 = reg_r14;

    // 0x8bef: mov qword ptr [rsp + 28h], rbp  [48 89 6c 24 28]
    unknown_operand = reg_rbp;

    // 0x8bf4: mov r8d, edi  [44 8b c7]
    reg_r8d = reg_edi;

    // 0x8bf7: mov qword ptr [rsp + 20h], rdx  [48 89 54 24 20]
    unknown_operand = reg_rdx;

    // 0x8bfc: mov rdx, rsi  [48 8b d6]
    reg_rdx = reg_rsi;

    // 0x8bff: mov rax, qword ptr [rax + 28h]  [48 8b 40 28]
    reg_rax = unknown_operand;

    // 0x8c03: call 0e010h  [e8 08 54 00 00]
    call_function_0xe010();
    // >>> Function call detected

    // 0x8c08: jmp 8badh  [eb a3]
    goto label_0x8bad;
    // >>> Control flow: Jump to 0x8bad


}

// ============================================
// Complete implementation of AmsiScanBuffer
// Original Address: 0x81a0
// Total Instructions: 64
// Basic Blocks: 3
// Register Usage: eax, edi, r11, r14, r15, r8, r8d, r9, r9d, rax, rbp, rbx, rcx, rdi, rdx, rsi, rsp
// ============================================
uint64_t AmsiScanBuffer(uint64_t param2, uint64_t param4) {
    // CPU Register simulation
    uint64_t reg_r11 = 0;  // General purpose register
    uint64_t reg_rdx = 0;  // Data register
    uint64_t reg_rbp = 0;  // Base pointer
    uint64_t reg_rsp = 0;  // Stack pointer
    uint64_t reg_r9d = 0;
    uint64_t reg_rax = 0;  // Accumulator register
    uint64_t reg_rsi = 0;  // Source index
    uint64_t reg_r14 = 0;  // General purpose register
    uint64_t reg_r9 = 0;  // General purpose register
    uint64_t reg_rdi = 0;  // Destination index
    uint64_t reg_rbx = 0;  // Base register
    uint64_t reg_rcx = 0;  // Counter register
    uint64_t reg_r8 = 0;  // General purpose register
    uint64_t reg_r8d = 0;
    uint64_t reg_r15 = 0;  // General purpose register

    // CPU Flags simulation
    bool zero_flag = false;
    bool carry_flag = false;
    bool sign_flag = false;
    bool overflow_flag = false;

    // ============= Basic Block 1 =============
    // Address Range: 0x81a0 - 0x8245
    // Instructions: 46

    // 0x81a0: mov qword ptr [rsp + 8], rbx  [48 89 5c 24 08]
    unknown_operand = reg_rbx;

    // 0x81a5: mov qword ptr [rsp + 10h], rbp  [48 89 6c 24 10]
    unknown_operand = reg_rbp;

    // 0x81aa: mov qword ptr [rsp + 18h], rsi  [48 89 74 24 18]
    unknown_operand = reg_rsi;

    // 0x81af: push rdi  [57]
    // PUSH reg_rdi

    // 0x81b0: push r14  [41 56]
    // PUSH reg_r14

    // 0x81b2: push r15  [41 57]
    // PUSH reg_r15

    // 0x81b4: sub rsp, 70h  [48 83 ec 70]
    reg_rsp -= 112;

    // 0x81b8: mov r15, r9  [4d 8b f9]
    reg_r15 = reg_r9;

    // 0x81bb: mov edi, r8d  [41 8b f8]
    reg_edi = reg_r8d;

    // 0x81be: mov rsi, rdx  [48 8b f2]
    reg_rsi = reg_rdx;

    // 0x81c1: mov rbx, rcx  [48 8b d9]
    reg_rbx = reg_rcx;

    // 0x81c4: mov rcx, qword ptr [rip + 0de7dh]  [48 8b 0d 7d de 00 00]
    reg_rcx = unknown_operand;

    // 0x81cb: lea rax, [rip + 0de76h]  [48 8d 05 76 de 00 00]
    reg_rax = &unknown_operand;

    // 0x81d2: mov rbp, qword ptr [rsp + 0b8h]  [48 8b ac 24 b8 00 00 00]
    reg_rbp = unknown_operand;

    // 0x81da: mov r14, qword ptr [rsp + 0b0h]  [4c 8b b4 24 b0 00 00 00]
    reg_r14 = unknown_operand;

    // 0x81e2: cmp rcx, rax  [48 3b c8]
    // Compare: reg_rcx vs reg_rax

    // 0x81e5: je 81edh  [74 06]
    if (zero_flag) goto label_0x81ed;
    // >>> Control flow: Jump to 0x81ed

    // 0x81e7: test byte ptr [rcx + 1ch], 4  [f6 41 1c 04]
    // Test: unknown_operand & 4

    // 0x81eb: jne 8267h  [75 7a]
    if (!zero_flag) goto label_0x8267;
    // >>> Control flow: Jump to 0x8267

    // 0x81ed: test rsi, rsi  [48 85 f6]
    // Test: reg_rsi & reg_rsi

    // 0x81f0: je 8247h  [74 55]
    if (zero_flag) goto label_0x8247;
    // >>> Control flow: Jump to 0x8247

    // 0x81f2: test edi, edi  [85 ff]
    // Test: reg_edi & reg_edi

    // 0x81f4: je 8247h  [74 51]
    if (zero_flag) goto label_0x8247;
    // >>> Control flow: Jump to 0x8247

    // 0x81f6: test rbp, rbp  [48 85 ed]
    // Test: reg_rbp & reg_rbp

    // 0x81f9: je 8247h  [74 4c]
    if (zero_flag) goto label_0x8247;
    // >>> Control flow: Jump to 0x8247

    // 0x81fb: test rbx, rbx  [48 85 db]
    // Test: reg_rbx & reg_rbx

    // 0x81fe: je 8247h  [74 47]
    if (zero_flag) goto label_0x8247;
    // >>> Control flow: Jump to 0x8247

    // 0x8200: mov r9, qword ptr [rbx + 8]  [4c 8b 4b 08]
    reg_r9 = unknown_operand;

    // 0x8204: test r9, r9  [4d 85 c9]
    // Test: reg_r9 & reg_r9

    // 0x8207: je 8247h  [74 3e]
    if (zero_flag) goto label_0x8247;
    // >>> Control flow: Jump to 0x8247

    // 0x8209: cmp qword ptr [rbx + 10h], 0  [48 83 7b 10 00]
    // Compare: unknown_operand vs 0

    // 0x820e: je 8247h  [74 37]
    if (zero_flag) goto label_0x8247;
    // >>> Control flow: Jump to 0x8247

    // 0x8210: mov qword ptr [rsp + 28h], r14  [4c 89 74 24 28]
    unknown_operand = reg_r14;

    // 0x8215: lea rcx, [rsp + 40h]  [48 8d 4c 24 40]
    reg_rcx = &unknown_operand;

    // 0x821a: mov r8d, edi  [44 8b c7]
    reg_r8d = reg_edi;

    // 0x821d: mov qword ptr [rsp + 20h], r15  [4c 89 7c 24 20]
    unknown_operand = reg_r15;

    // 0x8222: mov rdx, rsi  [48 8b d6]
    reg_rdx = reg_rsi;

    // 0x8225: call 8294h  [e8 6a 00 00 00]
    call_function_0x8294();
    // >>> Function call detected

    // 0x822a: mov rcx, qword ptr [rbx + 10h]  [48 8b 4b 10]
    reg_rcx = unknown_operand;

    // 0x822e: lea rdx, [rsp + 40h]  [48 8d 54 24 40]
    reg_rdx = &unknown_operand;

    // 0x8233: xor r9d, r9d  [45 33 c9]
    reg_r9d ^= reg_r9d;

    // 0x8236: mov r8, rbp  [4c 8b c5]
    reg_r8 = reg_rbp;

    // 0x8239: mov rax, qword ptr [rcx]  [48 8b 01]
    reg_rax = unknown_operand;

    // 0x823c: mov rax, qword ptr [rax + 18h]  [48 8b 40 18]
    reg_rax = unknown_operand;

    // 0x8240: call 0e010h  [e8 cb 5d 00 00]
    call_function_0xe010();
    // >>> Function call detected

    // 0x8245: jmp 824ch  [eb 05]
    goto label_0x824c;
    // >>> Control flow: Jump to 0x824c


label_0x8267:
    // ============= Basic Block 2 =============
    // Address Range: 0x8267 - 0x8286
    // Instructions: 8

    // 0x8267: mov rcx, qword ptr [rcx + 10h]  [48 8b 49 10]
    reg_rcx = unknown_operand;

    // 0x826b: mov r9, rbx  [4c 8b cb]
    reg_r9 = reg_rbx;

    // 0x826e: mov qword ptr [rsp + 38h], rbp  [48 89 6c 24 38]
    unknown_operand = reg_rbp;

    // 0x8273: mov qword ptr [rsp + 30h], r14  [4c 89 74 24 30]
    unknown_operand = reg_r14;

    // 0x8278: mov dword ptr [rsp + 28h], edi  [89 7c 24 28]
    unknown_operand = reg_edi;

    // 0x827c: mov qword ptr [rsp + 20h], rsi  [48 89 74 24 20]
    unknown_operand = reg_rsi;

    // 0x8281: call 0b968h  [e8 e2 36 00 00]
    call_function_0xb968();
    // >>> Function call detected

    // 0x8286: jmp 81edh  [e9 62 ff ff ff]
    goto label_0x81ed;
    // >>> Control flow: Jump to 0x81ed


label_0x8247:
    // ============= Basic Block 3 =============
    // Address Range: 0x8247 - 0x8265
    // Instructions: 10

    // 0x8247: mov eax, 80070057h  [b8 57 00 07 80]
    reg_eax = 2147942487;

    // 0x824c: lea r11, [rsp + 70h]  [4c 8d 5c 24 70]
    reg_r11 = &unknown_operand;

    // 0x8251: mov rbx, qword ptr [r11 + 20h]  [49 8b 5b 20]
    reg_rbx = unknown_operand;

    // 0x8255: mov rbp, qword ptr [r11 + 28h]  [49 8b 6b 28]
    reg_rbp = unknown_operand;

    // 0x8259: mov rsi, qword ptr [r11 + 30h]  [49 8b 73 30]
    reg_rsi = unknown_operand;

    // 0x825d: mov rsp, r11  [49 8b e3]
    reg_rsp = reg_r11;

    // 0x8260: pop r15  [41 5f]
    // POP reg_r15

    // 0x8262: pop r14  [41 5e]
    // POP reg_r14

    // 0x8264: pop rdi  [5f]
    // POP reg_rdi

    // 0x8265: ret   [c3]
    return result;
    // >>> Function return


}

// ============================================
// Complete implementation of DllGetClassObject
// Original Address: 0x75d0
// Total Instructions: 84
// Basic Blocks: 6
// Register Usage: eax, ebx, r14, r8, rax, rbp, rbx, rcx, rdi, rdx, rsi, rsp
// ============================================
uint64_t DllGetClassObject(uint64_t param1, uint64_t param3) {
    // CPU Register simulation
    uint64_t reg_rdx = 0;  // Data register
    uint64_t reg_rbp = 0;  // Base pointer
    uint64_t reg_rsp = 0;  // Stack pointer
    uint64_t reg_rax = 0;  // Accumulator register
    uint64_t reg_rsi = 0;  // Source index
    uint64_t reg_r14 = 0;  // General purpose register
    uint64_t reg_rdi = 0;  // Destination index
    uint64_t reg_rbx = 0;  // Base register
    uint64_t reg_rcx = 0;  // Counter register
    uint64_t reg_r8 = 0;  // General purpose register

    // CPU Flags simulation
    bool zero_flag = false;
    bool carry_flag = false;
    bool sign_flag = false;
    bool overflow_flag = false;

    // ============= Basic Block 1 =============
    // Address Range: 0x75d0 - 0x7697
    // Instructions: 59

    // 0x75d0: mov rax, rsp  [48 8b c4]
    reg_rax = reg_rsp;

    // 0x75d3: mov qword ptr [rax + 8], rbx  [48 89 58 08]
    unknown_operand = reg_rbx;

    // 0x75d7: mov qword ptr [rax + 10h], rbp  [48 89 68 10]
    unknown_operand = reg_rbp;

    // 0x75db: mov qword ptr [rax + 18h], rsi  [48 89 70 18]
    unknown_operand = reg_rsi;

    // 0x75df: mov qword ptr [rax + 20h], rdi  [48 89 78 20]
    unknown_operand = reg_rdi;

    // 0x75e3: push r14  [41 56]
    // PUSH reg_r14

    // 0x75e5: sub rsp, 20h  [48 83 ec 20]
    reg_rsp -= 32;

    // 0x75e9: cmp dword ptr [rip + 0f870h], 0  [83 3d 70 f8 00 00 00]
    // Compare: unknown_operand vs 0

    // 0x75f0: mov r14, r8  [4d 8b f0]
    reg_r14 = reg_r8;

    // 0x75f3: mov r8, rcx  [4c 8b c1]
    reg_r8 = reg_rcx;

    // 0x75f6: mov rbp, rdx  [48 8b ea]
    reg_rbp = reg_rdx;

    // 0x75f9: je 7699h  [0f 84 9a 00 00 00]
    if (zero_flag) goto label_0x7699;
    // >>> Control flow: Jump to 0x7699

    // 0x75ff: test r14, r14  [4d 85 f6]
    // Test: reg_r14 & reg_r14

    // 0x7602: je 76f2h  [0f 84 ea 00 00 00]
    if (zero_flag) goto label_0x76f2;
    // >>> Control flow: Jump to 0x76f2

    // 0x7608: and qword ptr [r14], 0  [49 83 26 00]
    unknown_operand &= 0;

    // 0x760c: mov rcx, qword ptr [rip + 0f85dh]  [48 8b 0d 5d f8 00 00]
    reg_rcx = unknown_operand;

    // 0x7613: xor ebx, ebx  [33 db]
    reg_ebx ^= reg_ebx;

    // 0x7615: cmp rcx, qword ptr [rip + 0f85ch]  [48 3b 0d 5c f8 00 00]
    // Compare: reg_rcx vs unknown_operand

    // 0x761c: jae 7675h  [73 57]
    // ASM: jae 7675h (Address: 0x761c)
    // >>> Control flow: Jump to 0x7675

    // 0x761e: mov rsi, qword ptr [rcx]  [48 8b 31]
    reg_rsi = unknown_operand;

    // 0x7621: test rsi, rsi  [48 85 f6]
    // Test: reg_rsi & reg_rsi

    // 0x7624: je 76a0h  [74 7a]
    if (zero_flag) goto label_0x76a0;
    // >>> Control flow: Jump to 0x76a0

    // 0x7626: cmp qword ptr [rsi + 10h], rbx  [48 39 5e 10]
    // Compare: unknown_operand vs reg_rbx

    // 0x762a: je 76a0h  [74 74]
    if (zero_flag) goto label_0x76a0;
    // >>> Control flow: Jump to 0x76a0

    // 0x762c: mov rdx, qword ptr [rsi]  [48 8b 16]
    reg_rdx = unknown_operand;

    // 0x762f: mov eax, dword ptr [rdx]  [8b 02]
    reg_eax = unknown_operand;

    // 0x7631: cmp dword ptr [r8], eax  [41 39 00]
    // Compare: unknown_operand vs reg_eax

    // 0x7634: jne 76a0h  [75 6a]
    if (!zero_flag) goto label_0x76a0;
    // >>> Control flow: Jump to 0x76a0

    // 0x7636: mov eax, dword ptr [rdx + 4]  [8b 42 04]
    reg_eax = unknown_operand;

    // 0x7639: cmp dword ptr [r8 + 4], eax  [41 39 40 04]
    // Compare: unknown_operand vs reg_eax

    // 0x763d: jne 76a0h  [75 61]
    if (!zero_flag) goto label_0x76a0;
    // >>> Control flow: Jump to 0x76a0

    // 0x763f: mov eax, dword ptr [rdx + 8]  [8b 42 08]
    reg_eax = unknown_operand;

    // 0x7642: cmp dword ptr [r8 + 8], eax  [41 39 40 08]
    // Compare: unknown_operand vs reg_eax

    // 0x7646: jne 76a0h  [75 58]
    if (!zero_flag) goto label_0x76a0;
    // >>> Control flow: Jump to 0x76a0

    // 0x7648: mov eax, dword ptr [rdx + 0ch]  [8b 42 0c]
    reg_eax = unknown_operand;

    // 0x764b: cmp dword ptr [r8 + 0ch], eax  [41 39 40 0c]
    // Compare: unknown_operand vs reg_eax

    // 0x764f: jne 76a0h  [75 4f]
    if (!zero_flag) goto label_0x76a0;
    // >>> Control flow: Jump to 0x76a0

    // 0x7651: lea rdi, [rsi + 20h]  [48 8d 7e 20]
    reg_rdi = &unknown_operand;

    // 0x7655: cmp qword ptr [rdi], rbx  [48 39 1f]
    // Compare: unknown_operand vs reg_rbx

    // 0x7658: je 76a9h  [74 4f]
    if (zero_flag) goto label_0x76a9;
    // >>> Control flow: Jump to 0x76a9

    // 0x765a: mov rcx, qword ptr [rdi]  [48 8b 0f]
    reg_rcx = unknown_operand;

    // 0x765d: test rcx, rcx  [48 85 c9]
    // Test: reg_rcx & reg_rcx

    // 0x7660: je 7675h  [74 13]
    if (zero_flag) goto label_0x7675;
    // >>> Control flow: Jump to 0x7675

    // 0x7662: mov rax, qword ptr [rcx]  [48 8b 01]
    reg_rax = unknown_operand;

    // 0x7665: mov r8, r14  [4d 8b c6]
    reg_r8 = reg_r14;

    // 0x7668: mov rdx, rbp  [48 8b d5]
    reg_rdx = reg_rbp;

    // 0x766b: mov rax, qword ptr [rax]  [48 8b 00]
    reg_rax = unknown_operand;

    // 0x766e: call 0e010h  [e8 9d 69 00 00]
    call_function_0xe010();
    // >>> Function call detected

    // 0x7673: mov ebx, eax  [8b d8]
    reg_ebx = reg_eax;

    // 0x7675: cmp qword ptr [r14], 0  [49 83 3e 00]
    // Compare: unknown_operand vs 0

    // 0x7679: je 76f9h  [74 7e]
    if (zero_flag) goto label_0x76f9;
    // >>> Control flow: Jump to 0x76f9

    // 0x767b: mov rbp, qword ptr [rsp + 38h]  [48 8b 6c 24 38]
    reg_rbp = unknown_operand;

    // 0x7680: mov eax, ebx  [8b c3]
    reg_eax = reg_ebx;

    // 0x7682: mov rbx, qword ptr [rsp + 30h]  [48 8b 5c 24 30]
    reg_rbx = unknown_operand;

    // 0x7687: mov rsi, qword ptr [rsp + 40h]  [48 8b 74 24 40]
    reg_rsi = unknown_operand;

    // 0x768c: mov rdi, qword ptr [rsp + 48h]  [48 8b 7c 24 48]
    reg_rdi = unknown_operand;

    // 0x7691: add rsp, 20h  [48 83 c4 20]
    reg_rsp += 32;

    // 0x7695: pop r14  [41 5e]
    // POP reg_r14

    // 0x7697: ret   [c3]
    return result;
    // >>> Function return


label_0x7699:
    // ============= Basic Block 2 =============
    // Address Range: 0x7699 - 0x769e
    // Instructions: 2

    // 0x7699: mov ebx, 8000ffffh  [bb ff ff 00 80]
    reg_ebx = 2147549183;

    // 0x769e: jmp 767bh  [eb db]
    goto label_0x767b;
    // >>> Control flow: Jump to 0x767b


label_0x76f2:
    // ============= Basic Block 3 =============
    // Address Range: 0x76f2 - 0x76f7
    // Instructions: 2

    // 0x76f2: mov ebx, 80004003h  [bb 03 40 00 80]
    reg_ebx = 2147500035;

    // 0x76f7: jmp 767bh  [eb 82]
    goto label_0x767b;
    // >>> Control flow: Jump to 0x767b


label_0x76a0:
    // ============= Basic Block 4 =============
    // Address Range: 0x76a0 - 0x76a4
    // Instructions: 2

    // 0x76a0: add rcx, 8  [48 83 c1 08]
    reg_rcx += 8;

    // 0x76a4: jmp 7615h  [e9 6c ff ff ff]
    goto label_0x7615;
    // >>> Control flow: Jump to 0x7615


label_0x76a9:
    // ============= Basic Block 5 =============
    // Address Range: 0x76a9 - 0x76ed
    // Instructions: 15

    // 0x76a9: lea rcx, [rip + 0f7d0h]  [48 8d 0d d0 f7 00 00]
    reg_rcx = &unknown_operand;

    // 0x76b0: call qword ptr [rip + 8931h]  [48 ff 15 31 89 00 00]
    // Function call
    // >>> Function call detected

    // 0x76b7: nop dword ptr [rax + rax]  [0f 1f 44 00 00]
    // ASM: nop dword ptr [rax + rax] (Address: 0x76b7)

    // 0x76bc: cmp qword ptr [rdi], rbx  [48 39 1f]
    // Compare: unknown_operand vs reg_rbx

    // 0x76bf: jne 76dah  [75 19]
    if (!zero_flag) goto label_0x76da;
    // >>> Control flow: Jump to 0x76da

    // 0x76c1: mov rcx, qword ptr [rsi + 18h]  [48 8b 4e 18]
    reg_rcx = unknown_operand;

    // 0x76c5: lea rdx, [rip + 90f4h]  [48 8d 15 f4 90 00 00]
    reg_rdx = &unknown_operand;

    // 0x76cc: mov rax, qword ptr [rsi + 10h]  [48 8b 46 10]
    reg_rax = unknown_operand;

    // 0x76d0: mov r8, rdi  [4c 8b c7]
    reg_r8 = reg_rdi;

    // 0x76d3: call 0e010h  [e8 38 69 00 00]
    call_function_0xe010();
    // >>> Function call detected

    // 0x76d8: mov ebx, eax  [8b d8]
    reg_ebx = reg_eax;

    // 0x76da: lea rcx, [rip + 0f79fh]  [48 8d 0d 9f f7 00 00]
    reg_rcx = &unknown_operand;

    // 0x76e1: call qword ptr [rip + 88f8h]  [48 ff 15 f8 88 00 00]
    // Function call
    // >>> Function call detected

    // 0x76e8: nop dword ptr [rax + rax]  [0f 1f 44 00 00]
    // ASM: nop dword ptr [rax + rax] (Address: 0x76e8)

    // 0x76ed: jmp 765ah  [e9 68 ff ff ff]
    goto label_0x765a;
    // >>> Control flow: Jump to 0x765a


label_0x76f9:
    // ============= Basic Block 6 =============
    // Address Range: 0x76f9 - 0x7703
    // Instructions: 4

    // 0x76f9: test ebx, ebx  [85 db]
    // Test: reg_ebx & reg_ebx

    // 0x76fb: mov eax, 80040111h  [b8 11 01 04 80]
    reg_eax = 2147746065;

    // 0x7700: cmove ebx, eax  [0f 44 d8]
    // ASM: cmove ebx, eax (Address: 0x7700)

    // 0x7703: jmp 767bh  [e9 73 ff ff ff]
    goto label_0x767b;
    // >>> Control flow: Jump to 0x767b


}

// ============================================
// Complete implementation of AmsiUacScan
// Original Address: 0x20a0
// Total Instructions: 85
// Basic Blocks: 6
// Register Usage: eax, ebx, edx, r14, r8, r9, r9d, rax, rbp, rbx, rcx, rdi, rdx, rsi, rsp
// ============================================
uint64_t AmsiUacScan(uint64_t param1, uint64_t param2, uint64_t param3, uint64_t param4) {
    // CPU Register simulation
    uint64_t reg_rdx = 0;  // Data register
    uint64_t reg_rbp = 0;  // Base pointer
    uint64_t reg_rsp = 0;  // Stack pointer
    uint64_t reg_r9d = 0;
    uint64_t reg_rax = 0;  // Accumulator register
    uint64_t reg_rsi = 0;  // Source index
    uint64_t reg_r14 = 0;  // General purpose register
    uint64_t reg_r9 = 0;  // General purpose register
    uint64_t reg_rdi = 0;  // Destination index
    uint64_t reg_rbx = 0;  // Base register
    uint64_t reg_rcx = 0;  // Counter register
    uint64_t reg_r8 = 0;  // General purpose register

    // CPU Flags simulation
    bool zero_flag = false;
    bool carry_flag = false;
    bool sign_flag = false;
    bool overflow_flag = false;

    // ============= Basic Block 1 =============
    // Address Range: 0x20a0 - 0x2147
    // Instructions: 51

    // 0x20a0: mov qword ptr [rsp + 10h], rbx  [48 89 5c 24 10]
    unknown_operand = reg_rbx;

    // 0x20a5: mov qword ptr [rsp + 18h], rbp  [48 89 6c 24 18]
    unknown_operand = reg_rbp;

    // 0x20aa: push rsi  [56]
    // PUSH reg_rsi

    // 0x20ab: push rdi  [57]
    // PUSH reg_rdi

    // 0x20ac: push r14  [41 56]
    // PUSH reg_r14

    // 0x20ae: sub rsp, 30h  [48 83 ec 30]
    reg_rsp -= 48;

    // 0x20b2: mov rsi, r9  [49 8b f1]
    reg_rsi = reg_r9;

    // 0x20b5: mov rbp, r8  [49 8b e8]
    reg_rbp = reg_r8;

    // 0x20b8: mov rdi, rdx  [48 8b fa]
    reg_rdi = reg_rdx;

    // 0x20bb: mov rbx, rcx  [48 8b d9]
    reg_rbx = reg_rcx;

    // 0x20be: lea r14, [rip + 13f83h]  [4c 8d 35 83 3f 01 00]
    reg_r14 = &unknown_operand;

    // 0x20c5: mov rcx, qword ptr [rip + 13f7ch]  [48 8b 0d 7c 3f 01 00]
    reg_rcx = unknown_operand;

    // 0x20cc: cmp rcx, r14  [49 3b ce]
    // Compare: reg_rcx vs reg_r14

    // 0x20cf: je 20dbh  [74 0a]
    if (zero_flag) goto label_0x20db;
    // >>> Control flow: Jump to 0x20db

    // 0x20d1: test byte ptr [rcx + 1ch], 4  [f6 41 1c 04]
    // Test: unknown_operand & 4

    // 0x20d5: jne 2161h  [0f 85 86 00 00 00]
    if (!zero_flag) goto label_0x2161;
    // >>> Control flow: Jump to 0x2161

    // 0x20db: test rbx, rbx  [48 85 db]
    // Test: reg_rbx & reg_rbx

    // 0x20de: je 2149h  [74 69]
    if (zero_flag) goto label_0x2149;
    // >>> Control flow: Jump to 0x2149

    // 0x20e0: cmp dword ptr [rbx], 49534d4fh  [81 3b 4f 4d 53 49]
    // Compare: unknown_operand vs 1230196047

    // 0x20e6: jne 2149h  [75 61]
    if (!zero_flag) goto label_0x2149;
    // >>> Control flow: Jump to 0x2149

    // 0x20e8: mov rcx, qword ptr [rbx + 8]  [48 8b 4b 08]
    reg_rcx = unknown_operand;

    // 0x20ec: test rcx, rcx  [48 85 c9]
    // Test: reg_rcx & reg_rcx

    // 0x20ef: je 2149h  [74 58]
    if (zero_flag) goto label_0x2149;
    // >>> Control flow: Jump to 0x2149

    // 0x20f1: test rdi, rdi  [48 85 ff]
    // Test: reg_rdi & reg_rdi

    // 0x20f4: je 2149h  [74 53]
    if (zero_flag) goto label_0x2149;
    // >>> Control flow: Jump to 0x2149

    // 0x20f6: test rbp, rbp  [48 85 ed]
    // Test: reg_rbp & reg_rbp

    // 0x20f9: je 2149h  [74 4e]
    if (zero_flag) goto label_0x2149;
    // >>> Control flow: Jump to 0x2149

    // 0x20fb: test rsi, rsi  [48 85 f6]
    // Test: reg_rsi & reg_rsi

    // 0x20fe: je 2149h  [74 49]
    if (zero_flag) goto label_0x2149;
    // >>> Control flow: Jump to 0x2149

    // 0x2100: and qword ptr [rsp + 50h], 0  [48 83 64 24 50 00]
    unknown_operand &= 0;

    // 0x2106: lea r9, [rsp + 50h]  [4c 8d 4c 24 50]
    reg_r9 = &unknown_operand;

    // 0x210b: mov r8, rbp  [4c 8b c5]
    reg_r8 = reg_rbp;

    // 0x210e: mov rdx, rdi  [48 8b d7]
    reg_rdx = reg_rdi;

    // 0x2111: call 21d8h  [e8 c2 00 00 00]
    call_function_0x21d8();
    // >>> Function call detected

    // 0x2116: mov ebx, eax  [8b d8]
    reg_ebx = reg_eax;

    // 0x2118: test eax, eax  [85 c0]
    // Test: reg_eax & reg_eax

    // 0x211a: js 217eh  [78 62]
    // ASM: js 217eh (Address: 0x211a)
    // >>> Control flow: Jump to 0x217e

    // 0x211c: and qword ptr [rsi], 0  [48 83 26 00]
    unknown_operand &= 0;

    // 0x2120: mov rbx, qword ptr [rsp + 50h]  [48 8b 5c 24 50]
    reg_rbx = unknown_operand;

    // 0x2125: test rbx, rbx  [48 85 db]
    // Test: reg_rbx & reg_rbx

    // 0x2128: jne 21b9h  [0f 85 8b 00 00 00]
    if (!zero_flag) goto label_0x21b9;
    // >>> Control flow: Jump to 0x21b9

    // 0x212e: test rbx, rbx  [48 85 db]
    // Test: reg_rbx & reg_rbx

    // 0x2131: jne 2150h  [75 1d]
    if (!zero_flag) goto label_0x2150;
    // >>> Control flow: Jump to 0x2150

    // 0x2133: xor eax, eax  [33 c0]
    reg_eax ^= reg_eax;

    // 0x2135: mov rbx, qword ptr [rsp + 58h]  [48 8b 5c 24 58]
    reg_rbx = unknown_operand;

    // 0x213a: mov rbp, qword ptr [rsp + 60h]  [48 8b 6c 24 60]
    reg_rbp = unknown_operand;

    // 0x213f: add rsp, 30h  [48 83 c4 30]
    reg_rsp += 48;

    // 0x2143: pop r14  [41 5e]
    // POP reg_r14

    // 0x2145: pop rdi  [5f]
    // POP reg_rdi

    // 0x2146: pop rsi  [5e]
    // POP reg_rsi

    // 0x2147: ret   [c3]
    return result;
    // >>> Function return


label_0x2161:
    // ============= Basic Block 2 =============
    // Address Range: 0x2161 - 0x2179
    // Instructions: 7

    // 0x2161: mov eax, dword ptr [rdx + 0ch]  [8b 42 0c]
    reg_eax = unknown_operand;

    // 0x2164: mov dword ptr [rsp + 28h], eax  [89 44 24 28]
    unknown_operand = reg_eax;

    // 0x2168: mov qword ptr [rsp + 20h], rdi  [48 89 7c 24 20]
    unknown_operand = reg_rdi;

    // 0x216d: mov r9, rbx  [4c 8b cb]
    reg_r9 = reg_rbx;

    // 0x2170: mov rcx, qword ptr [rcx + 10h]  [48 8b 49 10]
    reg_rcx = unknown_operand;

    // 0x2174: call 0b88ch  [e8 13 97 00 00]
    call_function_0xb88c();
    // >>> Function call detected

    // 0x2179: jmp 20dbh  [e9 5d ff ff ff]
    goto label_0x20db;
    // >>> Control flow: Jump to 0x20db


label_0x2149:
    // ============= Basic Block 3 =============
    // Address Range: 0x2149 - 0x214e
    // Instructions: 2

    // 0x2149: mov eax, 80070057h  [b8 57 00 07 80]
    reg_eax = 2147942487;

    // 0x214e: jmp 2135h  [eb e5]
    goto label_0x2135;
    // >>> Control flow: Jump to 0x2135


label_0x217e:
    // ============= Basic Block 4 =============
    // Address Range: 0x217e - 0x21b4
    // Instructions: 14

    // 0x217e: mov rcx, qword ptr [rip + 13ec3h]  [48 8b 0d c3 3e 01 00]
    reg_rcx = unknown_operand;

    // 0x2185: cmp rcx, r14  [49 3b ce]
    // Compare: reg_rcx vs reg_r14

    // 0x2188: je 21a8h  [74 1e]
    if (zero_flag) goto label_0x21a8;
    // >>> Control flow: Jump to 0x21a8

    // 0x218a: test byte ptr [rcx + 1ch], 1  [f6 41 1c 01]
    // Test: unknown_operand & 1

    // 0x218e: je 21a8h  [74 18]
    if (zero_flag) goto label_0x21a8;
    // >>> Control flow: Jump to 0x21a8

    // 0x2190: mov edx, 22h  [ba 22 00 00 00]
    reg_edx = 34;

    // 0x2195: mov r9d, ebx  [44 8b cb]
    reg_r9d = reg_ebx;

    // 0x2198: lea r8, [rip + 0e611h]  [4c 8d 05 11 e6 00 00]
    reg_r8 = &unknown_operand;

    // 0x219f: mov rcx, qword ptr [rcx + 10h]  [48 8b 49 10]
    reg_rcx = unknown_operand;

    // 0x21a3: call 91c4h  [e8 1c 70 00 00]
    call_function_0x91c4();
    // >>> Function call detected

    // 0x21a8: lea rcx, [rsp + 50h]  [48 8d 4c 24 50]
    reg_rcx = &unknown_operand;

    // 0x21ad: call 78b0h  [e8 fe 56 00 00]
    call_function_0x78b0();
    // >>> Function call detected

    // 0x21b2: mov eax, ebx  [8b c3]
    reg_eax = reg_ebx;

    // 0x21b4: jmp 2135h  [e9 7c ff ff ff]
    goto label_0x2135;
    // >>> Control flow: Jump to 0x2135


label_0x21b9:
    // ============= Basic Block 5 =============
    // Address Range: 0x21b9 - 0x21cb
    // Instructions: 6

    // 0x21b9: mov rax, qword ptr [rbx]  [48 8b 03]
    reg_rax = unknown_operand;

    // 0x21bc: mov rdx, rsi  [48 8b d6]
    reg_rdx = reg_rsi;

    // 0x21bf: mov rcx, rbx  [48 8b cb]
    reg_rcx = reg_rbx;

    // 0x21c2: mov rax, qword ptr [rax + 20h]  [48 8b 40 20]
    reg_rax = unknown_operand;

    // 0x21c6: call 0e010h  [e8 45 be 00 00]
    call_function_0xe010();
    // >>> Function call detected

    // 0x21cb: jmp 212eh  [e9 5e ff ff ff]
    goto label_0x212e;
    // >>> Control flow: Jump to 0x212e


label_0x2150:
    // ============= Basic Block 6 =============
    // Address Range: 0x2150 - 0x215f
    // Instructions: 5

    // 0x2150: mov rax, qword ptr [rbx]  [48 8b 03]
    reg_rax = unknown_operand;

    // 0x2153: mov rcx, rbx  [48 8b cb]
    reg_rcx = reg_rbx;

    // 0x2156: mov rax, qword ptr [rax + 10h]  [48 8b 40 10]
    reg_rax = unknown_operand;

    // 0x215a: call 0e010h  [e8 b1 be 00 00]
    call_function_0xe010();
    // >>> Function call detected

    // 0x215f: jmp 2133h  [eb d2]
    goto label_0x2133;
    // >>> Control flow: Jump to 0x2133


}

// ============================================
// Complete implementation of AmsiUacInitialize
// Original Address: 0x1570
// Total Instructions: 117
// Basic Blocks: 9
// Register Usage: eax, ebx, ecx, edx, r14, r8, r9, r9d, rax, rbp, rbx, rcx, rdi, rdx, rsi, rsp, xmm0
// ============================================
uint64_t AmsiUacInitialize(uint64_t param1) {
    // CPU Register simulation
    uint64_t reg_rdx = 0;  // Data register
    uint64_t reg_rbp = 0;  // Base pointer
    uint64_t reg_rsp = 0;  // Stack pointer
    uint64_t reg_r9d = 0;
    uint64_t reg_rax = 0;  // Accumulator register
    uint64_t reg_rsi = 0;  // Source index
    uint64_t reg_r14 = 0;  // General purpose register
    uint64_t reg_r9 = 0;  // General purpose register
    uint64_t reg_rdi = 0;  // Destination index
    uint64_t reg_xmm0 = 0;
    uint64_t reg_rbx = 0;  // Base register
    uint64_t reg_rcx = 0;  // Counter register
    uint64_t reg_r8 = 0;  // General purpose register

    // CPU Flags simulation
    bool zero_flag = false;
    bool carry_flag = false;
    bool sign_flag = false;
    bool overflow_flag = false;

    // ============= Basic Block 1 =============
    // Address Range: 0x1570 - 0x164f
    // Instructions: 55

    // 0x1570: mov rax, rsp  [48 8b c4]
    reg_rax = reg_rsp;

    // 0x1573: mov qword ptr [rax + 8], rbx  [48 89 58 08]
    unknown_operand = reg_rbx;

    // 0x1577: mov qword ptr [rax + 10h], rbp  [48 89 68 10]
    unknown_operand = reg_rbp;

    // 0x157b: mov qword ptr [rax + 18h], rsi  [48 89 70 18]
    unknown_operand = reg_rsi;

    // 0x157f: mov qword ptr [rax + 20h], rdi  [48 89 78 20]
    unknown_operand = reg_rdi;

    // 0x1583: push r14  [41 56]
    // PUSH reg_r14

    // 0x1585: sub rsp, 20h  [48 83 ec 20]
    reg_rsp -= 32;

    // 0x1589: mov rsi, rcx  [48 8b f1]
    reg_rsi = reg_rcx;

    // 0x158c: mov rcx, qword ptr [rip + 14ab5h]  [48 8b 0d b5 4a 01 00]
    reg_rcx = unknown_operand;

    // 0x1593: lea rbp, [rip + 14aaeh]  [48 8d 2d ae 4a 01 00]
    reg_rbp = &unknown_operand;

    // 0x159a: lea r14, [rip + 0f20fh]  [4c 8d 35 0f f2 00 00]
    reg_r14 = &unknown_operand;

    // 0x15a1: cmp rcx, rbp  [48 3b cd]
    // Compare: reg_rcx vs reg_rbp

    // 0x15a4: je 15b0h  [74 0a]
    if (zero_flag) goto label_0x15b0;
    // >>> Control flow: Jump to 0x15b0

    // 0x15a6: test byte ptr [rcx + 1ch], 4  [f6 41 1c 04]
    // Test: unknown_operand & 4

    // 0x15aa: jne 1696h  [0f 85 e6 00 00 00]
    if (!zero_flag) goto label_0x1696;
    // >>> Control flow: Jump to 0x1696

    // 0x15b0: test rsi, rsi  [48 85 f6]
    // Test: reg_rsi & reg_rsi

    // 0x15b3: je 1651h  [0f 84 98 00 00 00]
    if (zero_flag) goto label_0x1651;
    // >>> Control flow: Jump to 0x1651

    // 0x15b9: mov ecx, 20h  [b9 20 00 00 00]
    reg_ecx = 32;

    // 0x15be: call qword ptr [rip + 17a4bh]  [48 ff 15 4b 7a 01 00]
    // Function call
    // >>> Function call detected

    // 0x15c5: nop dword ptr [rax + rax]  [0f 1f 44 00 00]
    // ASM: nop dword ptr [rax + rax] (Address: 0x15c5)

    // 0x15ca: mov rdi, rax  [48 8b f8]
    reg_rdi = reg_rax;

    // 0x15cd: test rax, rax  [48 85 c0]
    // Test: reg_rax & reg_rax

    // 0x15d0: je 16cfh  [0f 84 f9 00 00 00]
    if (zero_flag) goto label_0x16cf;
    // >>> Control flow: Jump to 0x16cf

    // 0x15d6: xorps xmm0, xmm0  [0f 57 c0]
    // ASM: xorps xmm0, xmm0 (Address: 0x15d6)

    // 0x15d9: lea rdx, [rip + 0f258h]  [48 8d 15 58 f2 00 00]
    reg_rdx = &unknown_operand;

    // 0x15e0: movups xmmword ptr [rax], xmm0  [0f 11 00]
    // ASM: movups xmmword ptr [rax], xmm0 (Address: 0x15e0)

    // 0x15e3: mov ecx, 198h  [b9 98 01 00 00]
    reg_ecx = 408;

    // 0x15e8: movups xmmword ptr [rax + 10h], xmm0  [0f 11 40 10]
    // ASM: movups xmmword ptr [rax + 10h], xmm0 (Address: 0x15e8)

    // 0x15ec: mov dword ptr [rax], 49534d4fh  [c7 00 4f 4d 53 49]
    unknown_operand = 1230196047;

    // 0x15f2: call 99d8h  [e8 e1 83 00 00]
    call_function_0x99d8();
    // >>> Function call detected

    // 0x15f7: test rax, rax  [48 85 c0]
    // Test: reg_rax & reg_rax

    // 0x15fa: je 1604h  [74 08]
    if (zero_flag) goto label_0x1604;
    // >>> Control flow: Jump to 0x1604

    // 0x15fc: mov rcx, rax  [48 8b c8]
    reg_rcx = reg_rax;

    // 0x15ff: call 1910h  [e8 0c 03 00 00]
    call_function_0x1910();
    // >>> Function call detected

    // 0x1604: mov qword ptr [rdi + 8], rax  [48 89 47 08]
    unknown_operand = reg_rax;

    // 0x1608: test rax, rax  [48 85 c0]
    // Test: reg_rax & reg_rax

    // 0x160b: je 16fch  [0f 84 eb 00 00 00]
    if (zero_flag) goto label_0x16fc;
    // >>> Control flow: Jump to 0x16fc

    // 0x1611: mov rcx, rax  [48 8b c8]
    reg_rcx = reg_rax;

    // 0x1614: call 1748h  [e8 2f 01 00 00]
    call_function_0x1748();
    // >>> Function call detected

    // 0x1619: mov ebx, eax  [8b d8]
    reg_ebx = reg_eax;

    // 0x161b: test eax, eax  [85 c0]
    // Test: reg_eax & reg_eax

    // 0x161d: jns 1679h  [79 5a]
    // ASM: jns 1679h (Address: 0x161d)
    // >>> Control flow: Jump to 0x1679

    // 0x161f: mov rcx, qword ptr [rip + 14a22h]  [48 8b 0d 22 4a 01 00]
    reg_rcx = unknown_operand;

    // 0x1626: cmp rcx, rbp  [48 3b cd]
    // Compare: reg_rcx vs reg_rbp

    // 0x1629: jne 165dh  [75 32]
    if (!zero_flag) goto label_0x165d;
    // >>> Control flow: Jump to 0x165d

    // 0x162b: mov rcx, rdi  [48 8b cf]
    reg_rcx = reg_rdi;

    // 0x162e: call 18a0h  [e8 6d 02 00 00]
    call_function_0x18a0();
    // >>> Function call detected

    // 0x1633: mov eax, ebx  [8b c3]
    reg_eax = reg_ebx;

    // 0x1635: mov rbx, qword ptr [rsp + 30h]  [48 8b 5c 24 30]
    reg_rbx = unknown_operand;

    // 0x163a: mov rbp, qword ptr [rsp + 38h]  [48 8b 6c 24 38]
    reg_rbp = unknown_operand;

    // 0x163f: mov rsi, qword ptr [rsp + 40h]  [48 8b 74 24 40]
    reg_rsi = unknown_operand;

    // 0x1644: mov rdi, qword ptr [rsp + 48h]  [48 8b 7c 24 48]
    reg_rdi = unknown_operand;

    // 0x1649: add rsp, 20h  [48 83 c4 20]
    reg_rsp += 32;

    // 0x164d: pop r14  [41 5e]
    // POP reg_r14

    // 0x164f: ret   [c3]
    return result;
    // >>> Function return


label_0x1696:
    // ============= Basic Block 2 =============
    // Address Range: 0x1696 - 0x16b1
    // Instructions: 7

    // 0x1696: mov rcx, qword ptr [rcx + 10h]  [48 8b 49 10]
    reg_rcx = unknown_operand;

    // 0x169a: mov edx, 1ah  [ba 1a 00 00 00]
    reg_edx = 26;

    // 0x169f: mov r9, rsi  [4c 8b ce]
    reg_r9 = reg_rsi;

    // 0x16a2: mov r8, r14  [4d 8b c6]
    reg_r8 = reg_r14;

    // 0x16a5: call 0b848h  [e8 9e a1 00 00]
    call_function_0xb848();
    // >>> Function call detected

    // 0x16aa: mov rcx, qword ptr [rip + 14997h]  [48 8b 0d 97 49 01 00]
    reg_rcx = unknown_operand;

    // 0x16b1: jmp 15b0h  [e9 fa fe ff ff]
    goto label_0x15b0;
    // >>> Control flow: Jump to 0x15b0


label_0x1651:
    // ============= Basic Block 3 =============
    // Address Range: 0x1651 - 0x165b
    // Instructions: 4

    // 0x1651: cmp rcx, rbp  [48 3b cd]
    // Compare: reg_rcx vs reg_rbp

    // 0x1654: jne 16b6h  [75 60]
    if (!zero_flag) goto label_0x16b6;
    // >>> Control flow: Jump to 0x16b6

    // 0x1656: mov eax, 80070057h  [b8 57 00 07 80]
    reg_eax = 2147942487;

    // 0x165b: jmp 1635h  [eb d8]
    goto label_0x1635;
    // >>> Control flow: Jump to 0x1635


label_0x16cf:
    // ============= Basic Block 4 =============
    // Address Range: 0x16cf - 0x16f7
    // Instructions: 11

    // 0x16cf: mov rcx, qword ptr [rip + 14972h]  [48 8b 0d 72 49 01 00]
    reg_rcx = unknown_operand;

    // 0x16d6: cmp rcx, rbp  [48 3b cd]
    // Compare: reg_rcx vs reg_rbp

    // 0x16d9: je 16f2h  [74 17]
    if (zero_flag) goto label_0x16f2;
    // >>> Control flow: Jump to 0x16f2

    // 0x16db: test byte ptr [rcx + 1ch], 1  [f6 41 1c 01]
    // Test: unknown_operand & 1

    // 0x16df: je 16f2h  [74 11]
    if (zero_flag) goto label_0x16f2;
    // >>> Control flow: Jump to 0x16f2

    // 0x16e1: mov rcx, qword ptr [rcx + 10h]  [48 8b 49 10]
    reg_rcx = unknown_operand;

    // 0x16e5: mov edx, 1ch  [ba 1c 00 00 00]
    reg_edx = 28;

    // 0x16ea: mov r8, r14  [4d 8b c6]
    reg_r8 = reg_r14;

    // 0x16ed: call 928ch  [e8 9a 7b 00 00]
    call_function_0x928c();
    // >>> Function call detected

    // 0x16f2: mov eax, 8007000eh  [b8 0e 00 07 80]
    reg_eax = 2147942414;

    // 0x16f7: jmp 1635h  [e9 39 ff ff ff]
    goto label_0x1635;
    // >>> Control flow: Jump to 0x1635


label_0x16fc:
    // ============= Basic Block 5 =============
    // Address Range: 0x16fc - 0x1724
    // Instructions: 11

    // 0x16fc: mov rcx, qword ptr [rip + 14945h]  [48 8b 0d 45 49 01 00]
    reg_rcx = unknown_operand;

    // 0x1703: cmp rcx, rbp  [48 3b cd]
    // Compare: reg_rcx vs reg_rbp

    // 0x1706: je 171fh  [74 17]
    if (zero_flag) goto label_0x171f;
    // >>> Control flow: Jump to 0x171f

    // 0x1708: test byte ptr [rcx + 1ch], 1  [f6 41 1c 01]
    // Test: unknown_operand & 1

    // 0x170c: je 171fh  [74 11]
    if (zero_flag) goto label_0x171f;
    // >>> Control flow: Jump to 0x171f

    // 0x170e: mov rcx, qword ptr [rcx + 10h]  [48 8b 49 10]
    reg_rcx = unknown_operand;

    // 0x1712: mov edx, 1dh  [ba 1d 00 00 00]
    reg_edx = 29;

    // 0x1717: mov r8, r14  [4d 8b c6]
    reg_r8 = reg_r14;

    // 0x171a: call 928ch  [e8 6d 7b 00 00]
    call_function_0x928c();
    // >>> Function call detected

    // 0x171f: mov ebx, 8007000eh  [bb 0e 00 07 80]
    reg_ebx = 2147942414;

    // 0x1724: jmp 162bh  [e9 02 ff ff ff]
    goto label_0x162b;
    // >>> Control flow: Jump to 0x162b


label_0x1679:
    // ============= Basic Block 6 =============
    // Address Range: 0x1679 - 0x1694
    // Instructions: 8

    // 0x1679: mov qword ptr [rsi], rdi  [48 89 3e]
    unknown_operand = reg_rdi;

    // 0x167c: mov rcx, qword ptr [rip + 149c5h]  [48 8b 0d c5 49 01 00]
    reg_rcx = unknown_operand;

    // 0x1683: cmp rcx, rbp  [48 3b cd]
    // Compare: reg_rcx vs reg_rbp

    // 0x1686: je 1692h  [74 0a]
    if (zero_flag) goto label_0x1692;
    // >>> Control flow: Jump to 0x1692

    // 0x1688: test byte ptr [rcx + 1ch], 4  [f6 41 1c 04]
    // Test: unknown_operand & 4

    // 0x168c: jne 1729h  [0f 85 97 00 00 00]
    if (!zero_flag) goto label_0x1729;
    // >>> Control flow: Jump to 0x1729

    // 0x1692: xor ebx, ebx  [33 db]
    reg_ebx ^= reg_ebx;

    // 0x1694: jmp 1633h  [eb 9d]
    goto label_0x1633;
    // >>> Control flow: Jump to 0x1633


label_0x165d:
    // ============= Basic Block 7 =============
    // Address Range: 0x165d - 0x1677
    // Instructions: 8

    // 0x165d: test byte ptr [rcx + 1ch], 1  [f6 41 1c 01]
    // Test: unknown_operand & 1

    // 0x1661: je 162bh  [74 c8]
    if (zero_flag) goto label_0x162b;
    // >>> Control flow: Jump to 0x162b

    // 0x1663: mov rcx, qword ptr [rcx + 10h]  [48 8b 49 10]
    reg_rcx = unknown_operand;

    // 0x1667: mov edx, 1eh  [ba 1e 00 00 00]
    reg_edx = 30;

    // 0x166c: mov r9d, eax  [44 8b c8]
    reg_r9d = reg_eax;

    // 0x166f: mov r8, r14  [4d 8b c6]
    reg_r8 = reg_r14;

    // 0x1672: call 91c4h  [e8 4d 7b 00 00]
    call_function_0x91c4();
    // >>> Function call detected

    // 0x1677: jmp 162bh  [eb b2]
    goto label_0x162b;
    // >>> Control flow: Jump to 0x162b


label_0x16b6:
    // ============= Basic Block 8 =============
    // Address Range: 0x16b6 - 0x16cd
    // Instructions: 7

    // 0x16b6: test byte ptr [rcx + 1ch], 1  [f6 41 1c 01]
    // Test: unknown_operand & 1

    // 0x16ba: je 1656h  [74 9a]
    if (zero_flag) goto label_0x1656;
    // >>> Control flow: Jump to 0x1656

    // 0x16bc: mov rcx, qword ptr [rcx + 10h]  [48 8b 49 10]
    reg_rcx = unknown_operand;

    // 0x16c0: mov edx, 1bh  [ba 1b 00 00 00]
    reg_edx = 27;

    // 0x16c5: mov r8, r14  [4d 8b c6]
    reg_r8 = reg_r14;

    // 0x16c8: call 928ch  [e8 bf 7b 00 00]
    call_function_0x928c();
    // >>> Function call detected

    // 0x16cd: jmp 1656h  [eb 87]
    goto label_0x1656;
    // >>> Control flow: Jump to 0x1656


label_0x1729:
    // ============= Basic Block 9 =============
    // Address Range: 0x1729 - 0x173d
    // Instructions: 6

    // 0x1729: mov rcx, qword ptr [rcx + 10h]  [48 8b 49 10]
    reg_rcx = unknown_operand;

    // 0x172d: mov edx, 1fh  [ba 1f 00 00 00]
    reg_edx = 31;

    // 0x1732: mov r9, rdi  [4c 8b cf]
    reg_r9 = reg_rdi;

    // 0x1735: mov r8, r14  [4d 8b c6]
    reg_r8 = reg_r14;

    // 0x1738: call 0b848h  [e8 0b a1 00 00]
    call_function_0xb848();
    // >>> Function call detected

    // 0x173d: jmp 1692h  [e9 50 ff ff ff]
    goto label_0x1692;
    // >>> Control flow: Jump to 0x1692


}

// ============================================
// Complete implementation of AmsiInitialize
// Original Address: 0x6f40
// Total Instructions: 274
// Basic Blocks: 17
// Register Usage: bx, eax, ebx, ecx, edi, edx, r10, r10d, r12, r14, r15, r8, r8d, r9, r9d, rax, rbp, rbx, rcx, rdi, rdx, rsi, rsp, xmm0
// ============================================
uint64_t AmsiInitialize(uint64_t param1, uint64_t param2) {
    // CPU Register simulation
    uint64_t reg_rdx = 0;  // Data register
    uint64_t reg_r12 = 0;  // General purpose register
    uint64_t reg_rbp = 0;  // Base pointer
    uint64_t reg_rsp = 0;  // Stack pointer
    uint64_t reg_r9d = 0;
    uint64_t reg_rax = 0;  // Accumulator register
    uint64_t reg_rsi = 0;  // Source index
    uint64_t reg_r14 = 0;  // General purpose register
    uint64_t reg_r9 = 0;  // General purpose register
    uint64_t reg_rdi = 0;  // Destination index
    uint64_t reg_r10d = 0;
    uint64_t reg_xmm0 = 0;
    uint64_t reg_r10 = 0;  // General purpose register
    uint64_t reg_rbx = 0;  // Base register
    uint64_t reg_rcx = 0;  // Counter register
    uint64_t reg_r8 = 0;  // General purpose register
    uint64_t reg_r8d = 0;
    uint64_t reg_r15 = 0;  // General purpose register

    // CPU Flags simulation
    bool zero_flag = false;
    bool carry_flag = false;
    bool sign_flag = false;
    bool overflow_flag = false;

    // ============= Basic Block 1 =============
    // Address Range: 0x6f40 - 0x7168
    // Instructions: 134

    // 0x6f40: mov qword ptr [rsp + 10h], rbx  [48 89 5c 24 10]
    unknown_operand = reg_rbx;

    // 0x6f45: mov qword ptr [rsp + 18h], rbp  [48 89 6c 24 18]
    unknown_operand = reg_rbp;

    // 0x6f4a: push rsi  [56]
    // PUSH reg_rsi

    // 0x6f4b: push rdi  [57]
    // PUSH reg_rdi

    // 0x6f4c: push r12  [41 54]
    // PUSH reg_r12

    // 0x6f4e: push r14  [41 56]
    // PUSH reg_r14

    // 0x6f50: push r15  [41 57]
    // PUSH reg_r15

    // 0x6f52: sub rsp, 30h  [48 83 ec 30]
    reg_rsp -= 48;

    // 0x6f56: mov r15, rdx  [4c 8b fa]
    reg_r15 = reg_rdx;

    // 0x6f59: mov rsi, rcx  [48 8b f1]
    reg_rsi = reg_rcx;

    // 0x6f5c: lea r12, [rip + 0f0e5h]  [4c 8d 25 e5 f0 00 00]
    reg_r12 = &unknown_operand;

    // 0x6f63: mov rcx, qword ptr [rip + 0f0deh]  [48 8b 0d de f0 00 00]
    reg_rcx = unknown_operand;

    // 0x6f6a: cmp rcx, r12  [49 3b cc]
    // Compare: reg_rcx vs reg_r12

    // 0x6f6d: jne 716ah  [0f 85 f7 01 00 00]
    if (!zero_flag) goto label_0x716a;
    // >>> Control flow: Jump to 0x716a

    // 0x6f73: xor ebx, ebx  [33 db]
    reg_ebx ^= reg_ebx;

    // 0x6f75: mov qword ptr [rsp + 60h], rbx  [48 89 5c 24 60]
    unknown_operand = reg_rbx;

    // 0x6f7a: test rsi, rsi  [48 85 f6]
    // Test: reg_rsi & reg_rsi

    // 0x6f7d: je 7235h  [0f 84 b2 02 00 00]
    if (zero_flag) goto label_0x7235;
    // >>> Control flow: Jump to 0x7235

    // 0x6f83: test r15, r15  [4d 85 ff]
    // Test: reg_r15 & reg_r15

    // 0x6f86: je 7235h  [0f 84 a9 02 00 00]
    if (zero_flag) goto label_0x7235;
    // >>> Control flow: Jump to 0x7235

    // 0x6f8c: mov rdi, 0ffffffffffffffffh  [48 c7 c7 ff ff ff ff]
    reg_rdi = -1;

    // 0x6f93: inc rdi  [48 ff c7]
    reg_rdi++;

    // 0x6f96: cmp word ptr [rsi + rdi*2], bx  [66 39 1c 7e]
    // Compare: unknown_operand vs reg_bx

    // 0x6f9a: jne 6f93h  [75 f7]
    if (!zero_flag) goto label_0x6f93;
    // >>> Control flow: Jump to 0x6f93

    // 0x6f9c: inc rdi  [48 ff c7]
    reg_rdi++;

    // 0x6f9f: lea rax, [rdi - 2]  [48 8d 47 fe]
    reg_rax = &unknown_operand;

    // 0x6fa3: cmp rax, 7ffdh  [48 3d fd 7f 00 00]
    // Compare: reg_rax vs 32765

    // 0x6fa9: ja 7191h  [0f 87 e2 01 00 00]
    // ASM: ja 7191h (Address: 0x6fa9)
    // >>> Control flow: Jump to 0x7191

    // 0x6faf: mov ecx, 20h  [b9 20 00 00 00]
    reg_ecx = 32;

    // 0x6fb4: call qword ptr [rip + 12055h]  [48 ff 15 55 20 01 00]
    // Function call
    // >>> Function call detected

    // 0x6fbb: nop dword ptr [rax + rax]  [0f 1f 44 00 00]
    // ASM: nop dword ptr [rax + rax] (Address: 0x6fbb)

    // 0x6fc0: mov rbp, rax  [48 8b e8]
    reg_rbp = reg_rax;

    // 0x6fc3: test rax, rax  [48 85 c0]
    // Test: reg_rax & reg_rax

    // 0x6fc6: je 728fh  [0f 84 c3 02 00 00]
    if (zero_flag) goto label_0x728f;
    // >>> Control flow: Jump to 0x728f

    // 0x6fcc: xorps xmm0, xmm0  [0f 57 c0]
    // ASM: xorps xmm0, xmm0 (Address: 0x6fcc)

    // 0x6fcf: movups xmmword ptr [rax], xmm0  [0f 11 00]
    // ASM: movups xmmword ptr [rax], xmm0 (Address: 0x6fcf)

    // 0x6fd2: movups xmmword ptr [rax + 10h], xmm0  [0f 11 40 10]
    // ASM: movups xmmword ptr [rax + 10h], xmm0 (Address: 0x6fd2)

    // 0x6fd6: add rdi, rdi  [48 03 ff]
    reg_rdi += reg_rdi;

    // 0x6fd9: mov rcx, rdi  [48 8b cf]
    reg_rcx = reg_rdi;

    // 0x6fdc: call qword ptr [rip + 1202dh]  [48 ff 15 2d 20 01 00]
    // Function call
    // >>> Function call detected

    // 0x6fe3: nop dword ptr [rax + rax]  [0f 1f 44 00 00]
    // ASM: nop dword ptr [rax + rax] (Address: 0x6fe3)

    // 0x6fe8: mov qword ptr [rbp + 8], rax  [48 89 45 08]
    unknown_operand = reg_rax;

    // 0x6fec: test rax, rax  [48 85 c0]
    // Test: reg_rax & reg_rax

    // 0x6fef: je 72d8h  [0f 84 e3 02 00 00]
    if (zero_flag) goto label_0x72d8;
    // >>> Control flow: Jump to 0x72d8

    // 0x6ff5: mov r8, rdi  [4c 8b c7]
    reg_r8 = reg_rdi;

    // 0x6ff8: mov rdx, rsi  [48 8b d6]
    reg_rdx = reg_rsi;

    // 0x6ffb: mov rcx, rax  [48 8b c8]
    reg_rcx = reg_rax;

    // 0x6ffe: call 0a2d8h  [e8 d5 32 00 00]
    call_function_0xa2d8();
    // >>> Function call detected

    // 0x7003: cmp dword ptr [rip + 0fe57h], ebx  [39 1d 57 fe 00 00]
    // Compare: unknown_operand vs reg_ebx

    // 0x7009: je 71b6h  [0f 84 a7 01 00 00]
    if (zero_flag) goto label_0x71b6;
    // >>> Control flow: Jump to 0x71b6

    // 0x700f: mov edi, ebx  [8b fb]
    reg_edi = reg_ebx;

    // 0x7011: mov rax, qword ptr [rip + 0fe58h]  [48 8b 05 58 fe 00 00]
    reg_rax = unknown_operand;

    // 0x7018: mov rdx, qword ptr [rip + 0fe59h]  [48 8b 15 59 fe 00 00]
    reg_rdx = unknown_operand;

    // 0x701f: mov r8d, dword ptr [rip + 9786h]  [44 8b 05 86 97 00 00]
    reg_r8d = unknown_operand;

    // 0x7026: mov r9, qword ptr [rip + 977bh]  [4c 8b 0d 7b 97 00 00]
    reg_r9 = unknown_operand;

    // 0x702d: mov r10, qword ptr [rip + 9770h]  [4c 8b 15 70 97 00 00]
    reg_r10 = unknown_operand;

    // 0x7034: cmp rax, rdx  [48 3b c2]
    // Compare: reg_rax vs reg_rdx

    // 0x7037: jae 70a8h  [73 6f]
    // ASM: jae 70a8h (Address: 0x7037)
    // >>> Control flow: Jump to 0x70a8

    // 0x7039: mov rsi, qword ptr [rax]  [48 8b 30]
    reg_rsi = unknown_operand;

    // 0x703c: test rsi, rsi  [48 85 f6]
    // Test: reg_rsi & reg_rsi

    // 0x703f: je 71f2h  [0f 84 ad 01 00 00]
    if (zero_flag) goto label_0x71f2;
    // >>> Control flow: Jump to 0x71f2

    // 0x7045: cmp qword ptr [rsi + 10h], rbx  [48 39 5e 10]
    // Compare: unknown_operand vs reg_rbx

    // 0x7049: je 71f2h  [0f 84 a3 01 00 00]
    if (zero_flag) goto label_0x71f2;
    // >>> Control flow: Jump to 0x71f2

    // 0x704f: mov rcx, qword ptr [rsi]  [48 8b 0e]
    reg_rcx = unknown_operand;

    // 0x7052: cmp dword ptr [rcx], 0fdb00e52h  [81 39 52 0e b0 fd]
    // Compare: unknown_operand vs 4256173650

    // 0x7058: jne 71f2h  [0f 85 94 01 00 00]
    if (!zero_flag) goto label_0x71f2;
    // >>> Control flow: Jump to 0x71f2

    // 0x705e: cmp r10d, dword ptr [rcx + 4]  [44 3b 51 04]
    // Compare: reg_r10d vs unknown_operand

    // 0x7062: jne 71f2h  [0f 85 8a 01 00 00]
    if (!zero_flag) goto label_0x71f2;
    // >>> Control flow: Jump to 0x71f2

    // 0x7068: cmp r9d, dword ptr [rcx + 8]  [44 3b 49 08]
    // Compare: reg_r9d vs unknown_operand

    // 0x706c: jne 71f2h  [0f 85 80 01 00 00]
    if (!zero_flag) goto label_0x71f2;
    // >>> Control flow: Jump to 0x71f2

    // 0x7072: cmp r8d, dword ptr [rcx + 0ch]  [44 3b 41 0c]
    // Compare: reg_r8d vs unknown_operand

    // 0x7076: jne 71f2h  [0f 85 76 01 00 00]
    if (!zero_flag) goto label_0x71f2;
    // >>> Control flow: Jump to 0x71f2

    // 0x707c: cmp qword ptr [rsi + 20h], rbx  [48 39 5e 20]
    // Compare: unknown_operand vs reg_rbx

    // 0x7080: je 7316h  [0f 84 90 02 00 00]
    if (zero_flag) goto label_0x7316;
    // >>> Control flow: Jump to 0x7316

    // 0x7086: mov rcx, qword ptr [rsi + 20h]  [48 8b 4e 20]
    reg_rcx = unknown_operand;

    // 0x708a: test rcx, rcx  [48 85 c9]
    // Test: reg_rcx & reg_rcx

    // 0x708d: je 70a8h  [74 19]
    if (zero_flag) goto label_0x70a8;
    // >>> Control flow: Jump to 0x70a8

    // 0x708f: mov rax, qword ptr [rcx]  [48 8b 01]
    reg_rax = unknown_operand;

    // 0x7092: lea r8, [rsp + 60h]  [4c 8d 44 24 60]
    reg_r8 = &unknown_operand;

    // 0x7097: lea rdx, [rip + 96f2h]  [48 8d 15 f2 96 00 00]
    reg_rdx = &unknown_operand;

    // 0x709e: mov rax, qword ptr [rax]  [48 8b 00]
    reg_rax = unknown_operand;

    // 0x70a1: call 0e010h  [e8 6a 6f 00 00]
    call_function_0xe010();
    // >>> Function call detected

    // 0x70a6: mov edi, eax  [8b f8]
    reg_edi = reg_eax;

    // 0x70a8: mov rcx, qword ptr [rsp + 60h]  [48 8b 4c 24 60]
    reg_rcx = unknown_operand;

    // 0x70ad: test rcx, rcx  [48 85 c9]
    // Test: reg_rcx & reg_rcx

    // 0x70b0: je 7361h  [0f 84 ab 02 00 00]
    if (zero_flag) goto label_0x7361;
    // >>> Control flow: Jump to 0x7361

    // 0x70b6: mov r9d, edi  [44 8b cf]
    reg_r9d = reg_edi;

    // 0x70b9: test edi, edi  [85 ff]
    // Test: reg_edi & reg_edi

    // 0x70bb: js 71beh  [0f 88 fd 00 00 00]
    // ASM: js 71beh (Address: 0x70bb)
    // >>> Control flow: Jump to 0x71be

    // 0x70c1: mov rax, qword ptr [rcx]  [48 8b 01]
    reg_rax = unknown_operand;

    // 0x70c4: lea r9, [rbp + 10h]  [4c 8d 4d 10]
    reg_r9 = &unknown_operand;

    // 0x70c8: lea r8, [rip + 96b1h]  [4c 8d 05 b1 96 00 00]
    reg_r8 = &unknown_operand;

    // 0x70cf: xor edx, edx  [33 d2]
    reg_edx ^= reg_edx;

    // 0x70d1: mov rax, qword ptr [rax + 18h]  [48 8b 40 18]
    reg_rax = unknown_operand;

    // 0x70d5: call 0e010h  [e8 36 6f 00 00]
    call_function_0xe010();
    // >>> Function call detected

    // 0x70da: mov edi, eax  [8b f8]
    reg_edi = reg_eax;

    // 0x70dc: test eax, eax  [85 c0]
    // Test: reg_eax & reg_eax

    // 0x70de: jns 7243h  [0f 89 5f 01 00 00]
    // ASM: jns 7243h (Address: 0x70de)
    // >>> Control flow: Jump to 0x7243

    // 0x70e4: mov rcx, qword ptr [rip + 0ef5dh]  [48 8b 0d 5d ef 00 00]
    reg_rcx = unknown_operand;

    // 0x70eb: cmp rcx, r12  [49 3b cc]
    // Compare: reg_rcx vs reg_r12

    // 0x70ee: je 70fah  [74 0a]
    if (zero_flag) goto label_0x70fa;
    // >>> Control flow: Jump to 0x70fa

    // 0x70f0: test byte ptr [rcx + 1ch], 1  [f6 41 1c 01]
    // Test: unknown_operand & 1

    // 0x70f4: jne 7309h  [0f 85 0f 02 00 00]
    if (!zero_flag) goto label_0x7309;
    // >>> Control flow: Jump to 0x7309

    // 0x70fa: mov rcx, qword ptr [rbp + 8]  [48 8b 4d 08]
    reg_rcx = unknown_operand;

    // 0x70fe: cmp dword ptr [rbp], 49534d4fh  [81 7d 00 4f 4d 53 49]
    // Compare: unknown_operand vs 1230196047

    // 0x7105: je 71fbh  [0f 84 f0 00 00 00]
    if (zero_flag) goto label_0x71fb;
    // >>> Control flow: Jump to 0x71fb

    // 0x710b: test rcx, rcx  [48 85 c9]
    // Test: reg_rcx & reg_rcx

    // 0x710e: je 711ch  [74 0c]
    if (zero_flag) goto label_0x711c;
    // >>> Control flow: Jump to 0x711c

    // 0x7110: call qword ptr [rip + 11f01h]  [48 ff 15 01 1f 01 00]
    // Function call
    // >>> Function call detected

    // 0x7117: nop dword ptr [rax + rax]  [0f 1f 44 00 00]
    // ASM: nop dword ptr [rax + rax] (Address: 0x7117)

    // 0x711c: mov rcx, qword ptr [rbp + 10h]  [48 8b 4d 10]
    reg_rcx = unknown_operand;

    // 0x7120: test rcx, rcx  [48 85 c9]
    // Test: reg_rcx & reg_rcx

    // 0x7123: jne 7224h  [0f 85 fb 00 00 00]
    if (!zero_flag) goto label_0x7224;
    // >>> Control flow: Jump to 0x7224

    // 0x7129: mov rcx, rbp  [48 8b cd]
    reg_rcx = reg_rbp;

    // 0x712c: call qword ptr [rip + 11ee5h]  [48 ff 15 e5 1e 01 00]
    // Function call
    // >>> Function call detected

    // 0x7133: nop dword ptr [rax + rax]  [0f 1f 44 00 00]
    // ASM: nop dword ptr [rax + rax] (Address: 0x7133)

    // 0x7138: nop   [90]
    // ASM: nop  (Address: 0x7138)

    // 0x7139: mov rcx, qword ptr [rsp + 60h]  [48 8b 4c 24 60]
    reg_rcx = unknown_operand;

    // 0x713e: test rcx, rcx  [48 85 c9]
    // Test: reg_rcx & reg_rcx

    // 0x7141: je 7150h  [74 0d]
    if (zero_flag) goto label_0x7150;
    // >>> Control flow: Jump to 0x7150

    // 0x7143: mov rax, qword ptr [rcx]  [48 8b 01]
    reg_rax = unknown_operand;

    // 0x7146: mov rax, qword ptr [rax + 10h]  [48 8b 40 10]
    reg_rax = unknown_operand;

    // 0x714a: call 0e010h  [e8 c1 6e 00 00]
    call_function_0xe010();
    // >>> Function call detected

    // 0x714f: nop   [90]
    // ASM: nop  (Address: 0x714f)

    // 0x7150: mov eax, edi  [8b c7]
    reg_eax = reg_edi;

    // 0x7152: mov rbx, qword ptr [rsp + 68h]  [48 8b 5c 24 68]
    reg_rbx = unknown_operand;

    // 0x7157: mov rbp, qword ptr [rsp + 70h]  [48 8b 6c 24 70]
    reg_rbp = unknown_operand;

    // 0x715c: add rsp, 30h  [48 83 c4 30]
    reg_rsp += 48;

    // 0x7160: pop r15  [41 5f]
    // POP reg_r15

    // 0x7162: pop r14  [41 5e]
    // POP reg_r14

    // 0x7164: pop r12  [41 5c]
    // POP reg_r12

    // 0x7166: pop rdi  [5f]
    // POP reg_rdi

    // 0x7167: pop rsi  [5e]
    // POP reg_rsi

    // 0x7168: ret   [c3]
    return result;
    // >>> Function return


label_0x716a:
    // ============= Basic Block 2 =============
    // Address Range: 0x716a - 0x718c
    // Instructions: 8

    // 0x716a: test byte ptr [rcx + 1ch], 4  [f6 41 1c 04]
    // Test: unknown_operand & 4

    // 0x716e: je 6f73h  [0f 84 ff fd ff ff]
    if (zero_flag) goto label_0x6f73;
    // >>> Control flow: Jump to 0x6f73

    // 0x7174: mov qword ptr [rsp + 20h], r15  [4c 89 7c 24 20]
    unknown_operand = reg_r15;

    // 0x7179: mov r9, rsi  [4c 8b ce]
    reg_r9 = reg_rsi;

    // 0x717c: mov rcx, qword ptr [rcx + 10h]  [48 8b 49 10]
    reg_rcx = unknown_operand;

    // 0x7180: call 73dch  [e8 57 02 00 00]
    call_function_0x73dc();
    // >>> Function call detected

    // 0x7185: mov rcx, qword ptr [rip + 0eebch]  [48 8b 0d bc ee 00 00]
    reg_rcx = unknown_operand;

    // 0x718c: jmp 6f73h  [e9 e2 fd ff ff]
    goto label_0x6f73;
    // >>> Control flow: Jump to 0x6f73


label_0x7235:
    // ============= Basic Block 3 =============
    // Address Range: 0x7235 - 0x723e
    // Instructions: 3

    // 0x7235: cmp rcx, r12  [49 3b cc]
    // Compare: reg_rcx vs reg_r12

    // 0x7238: jne 73adh  [0f 85 6f 01 00 00]
    if (!zero_flag) goto label_0x73ad;
    // >>> Control flow: Jump to 0x73ad

    // 0x723e: jmp 719ah  [e9 57 ff ff ff]
    goto label_0x719a;
    // >>> Control flow: Jump to 0x719a


label_0x7191:
    // ============= Basic Block 4 =============
    // Address Range: 0x7191 - 0x71b4
    // Instructions: 11

    // 0x7191: cmp rcx, r12  [49 3b cc]
    // Compare: reg_rcx vs reg_r12

    // 0x7194: jne 738dh  [0f 85 f3 01 00 00]
    if (!zero_flag) goto label_0x738d;
    // >>> Control flow: Jump to 0x738d

    // 0x719a: test rbx, rbx  [48 85 db]
    // Test: reg_rbx & reg_rbx

    // 0x719d: je 71afh  [74 10]
    if (zero_flag) goto label_0x71af;
    // >>> Control flow: Jump to 0x71af

    // 0x719f: mov rax, qword ptr [rbx]  [48 8b 03]
    reg_rax = unknown_operand;

    // 0x71a2: mov rcx, rbx  [48 8b cb]
    reg_rcx = reg_rbx;

    // 0x71a5: mov rax, qword ptr [rax + 10h]  [48 8b 40 10]
    reg_rax = unknown_operand;

    // 0x71a9: call 0e010h  [e8 62 6e 00 00]
    call_function_0xe010();
    // >>> Function call detected

    // 0x71ae: nop   [90]
    // ASM: nop  (Address: 0x71ae)

    // 0x71af: mov eax, 80070057h  [b8 57 00 07 80]
    reg_eax = 2147942487;

    // 0x71b4: jmp 7152h  [eb 9c]
    goto label_0x7152;
    // >>> Control flow: Jump to 0x7152


label_0x728f:
    // ============= Basic Block 5 =============
    // Address Range: 0x728f - 0x72d3
    // Instructions: 19

    // 0x728f: mov rcx, qword ptr [rip + 0edb2h]  [48 8b 0d b2 ed 00 00]
    reg_rcx = unknown_operand;

    // 0x7296: cmp rcx, r12  [49 3b cc]
    // Compare: reg_rcx vs reg_r12

    // 0x7299: je 72b7h  [74 1c]
    if (zero_flag) goto label_0x72b7;
    // >>> Control flow: Jump to 0x72b7

    // 0x729b: test byte ptr [rcx + 1ch], 1  [f6 41 1c 01]
    // Test: unknown_operand & 1

    // 0x729f: je 72b7h  [74 16]
    if (zero_flag) goto label_0x72b7;
    // >>> Control flow: Jump to 0x72b7

    // 0x72a1: mov edx, 12h  [ba 12 00 00 00]
    reg_edx = 18;

    // 0x72a6: lea r8, [rip + 9503h]  [4c 8d 05 03 95 00 00]
    reg_r8 = &unknown_operand;

    // 0x72ad: mov rcx, qword ptr [rcx + 10h]  [48 8b 49 10]
    reg_rcx = unknown_operand;

    // 0x72b1: call 928ch  [e8 d6 1f 00 00]
    call_function_0x928c();
    // >>> Function call detected

    // 0x72b6: nop   [90]
    // ASM: nop  (Address: 0x72b6)

    // 0x72b7: mov rcx, qword ptr [rsp + 60h]  [48 8b 4c 24 60]
    reg_rcx = unknown_operand;

    // 0x72bc: test rcx, rcx  [48 85 c9]
    // Test: reg_rcx & reg_rcx

    // 0x72bf: je 72ceh  [74 0d]
    if (zero_flag) goto label_0x72ce;
    // >>> Control flow: Jump to 0x72ce

    // 0x72c1: mov rax, qword ptr [rcx]  [48 8b 01]
    reg_rax = unknown_operand;

    // 0x72c4: mov rax, qword ptr [rax + 10h]  [48 8b 40 10]
    reg_rax = unknown_operand;

    // 0x72c8: call 0e010h  [e8 43 6d 00 00]
    call_function_0xe010();
    // >>> Function call detected

    // 0x72cd: nop   [90]
    // ASM: nop  (Address: 0x72cd)

    // 0x72ce: mov eax, 8007000eh  [b8 0e 00 07 80]
    reg_eax = 2147942414;

    // 0x72d3: jmp 7152h  [e9 7a fe ff ff]
    goto label_0x7152;
    // >>> Control flow: Jump to 0x7152


label_0x72d8:
    // ============= Basic Block 6 =============
    // Address Range: 0x72d8 - 0x7304
    // Instructions: 11

    // 0x72d8: mov rcx, qword ptr [rip + 0ed69h]  [48 8b 0d 69 ed 00 00]
    reg_rcx = unknown_operand;

    // 0x72df: cmp rcx, r12  [49 3b cc]
    // Compare: reg_rcx vs reg_r12

    // 0x72e2: je 72ffh  [74 1b]
    if (zero_flag) goto label_0x72ff;
    // >>> Control flow: Jump to 0x72ff

    // 0x72e4: test byte ptr [rcx + 1ch], 1  [f6 41 1c 01]
    // Test: unknown_operand & 1

    // 0x72e8: je 72ffh  [74 15]
    if (zero_flag) goto label_0x72ff;
    // >>> Control flow: Jump to 0x72ff

    // 0x72ea: mov edx, 13h  [ba 13 00 00 00]
    reg_edx = 19;

    // 0x72ef: lea r8, [rip + 94bah]  [4c 8d 05 ba 94 00 00]
    reg_r8 = &unknown_operand;

    // 0x72f6: mov rcx, qword ptr [rcx + 10h]  [48 8b 49 10]
    reg_rcx = unknown_operand;

    // 0x72fa: call 928ch  [e8 8d 1f 00 00]
    call_function_0x928c();
    // >>> Function call detected

    // 0x72ff: mov edi, 8007000eh  [bf 0e 00 07 80]
    reg_edi = 2147942414;

    // 0x7304: jmp 70fah  [e9 f1 fd ff ff]
    goto label_0x70fa;
    // >>> Control flow: Jump to 0x70fa


label_0x71b6:
    // ============= Basic Block 7 =============
    // Address Range: 0x71b6 - 0x71ed
    // Instructions: 12

    // 0x71b6: mov edi, 8000ffffh  [bf ff ff 00 80]
    reg_edi = 2147549183;

    // 0x71bb: mov r9d, edi  [44 8b cf]
    reg_r9d = reg_edi;

    // 0x71be: mov rcx, qword ptr [rip + 0ee83h]  [48 8b 0d 83 ee 00 00]
    reg_rcx = unknown_operand;

    // 0x71c5: cmp rcx, r12  [49 3b cc]
    // Compare: reg_rcx vs reg_r12

    // 0x71c8: je 70fah  [0f 84 2c ff ff ff]
    if (zero_flag) goto label_0x70fa;
    // >>> Control flow: Jump to 0x70fa

    // 0x71ce: test byte ptr [rcx + 1ch], 1  [f6 41 1c 01]
    // Test: unknown_operand & 1

    // 0x71d2: je 70fah  [0f 84 22 ff ff ff]
    if (zero_flag) goto label_0x70fa;
    // >>> Control flow: Jump to 0x70fa

    // 0x71d8: mov edx, 14h  [ba 14 00 00 00]
    reg_edx = 20;

    // 0x71dd: lea r8, [rip + 95cch]  [4c 8d 05 cc 95 00 00]
    reg_r8 = &unknown_operand;

    // 0x71e4: mov rcx, qword ptr [rcx + 10h]  [48 8b 49 10]
    reg_rcx = unknown_operand;

    // 0x71e8: call 91c4h  [e8 d7 1f 00 00]
    call_function_0x91c4();
    // >>> Function call detected

    // 0x71ed: jmp 70fah  [e9 08 ff ff ff]
    goto label_0x70fa;
    // >>> Control flow: Jump to 0x70fa


label_0x71f2:
    // ============= Basic Block 8 =============
    // Address Range: 0x71f2 - 0x71f6
    // Instructions: 2

    // 0x71f2: add rax, 8  [48 83 c0 08]
    reg_rax += 8;

    // 0x71f6: jmp 7034h  [e9 39 fe ff ff]
    goto label_0x7034;
    // >>> Control flow: Jump to 0x7034


label_0x7316:
    // ============= Basic Block 9 =============
    // Address Range: 0x7316 - 0x735c
    // Instructions: 15

    // 0x7316: lea rcx, [rip + 0fb63h]  [48 8d 0d 63 fb 00 00]
    reg_rcx = &unknown_operand;

    // 0x731d: call qword ptr [rip + 8cc4h]  [48 ff 15 c4 8c 00 00]
    // Function call
    // >>> Function call detected

    // 0x7324: nop dword ptr [rax + rax]  [0f 1f 44 00 00]
    // ASM: nop dword ptr [rax + rax] (Address: 0x7324)

    // 0x7329: cmp qword ptr [rsi + 20h], rbx  [48 39 5e 20]
    // Compare: unknown_operand vs reg_rbx

    // 0x732d: jne 7349h  [75 1a]
    if (!zero_flag) goto label_0x7349;
    // >>> Control flow: Jump to 0x7349

    // 0x732f: lea r8, [rsi + 20h]  [4c 8d 46 20]
    reg_r8 = &unknown_operand;

    // 0x7333: lea rdx, [rip + 9486h]  [48 8d 15 86 94 00 00]
    reg_rdx = &unknown_operand;

    // 0x733a: mov rcx, qword ptr [rsi + 18h]  [48 8b 4e 18]
    reg_rcx = unknown_operand;

    // 0x733e: mov rax, qword ptr [rsi + 10h]  [48 8b 46 10]
    reg_rax = unknown_operand;

    // 0x7342: call 0e010h  [e8 c9 6c 00 00]
    call_function_0xe010();
    // >>> Function call detected

    // 0x7347: mov edi, eax  [8b f8]
    reg_edi = reg_eax;

    // 0x7349: lea rcx, [rip + 0fb30h]  [48 8d 0d 30 fb 00 00]
    reg_rcx = &unknown_operand;

    // 0x7350: call qword ptr [rip + 8c89h]  [48 ff 15 89 8c 00 00]
    // Function call
    // >>> Function call detected

    // 0x7357: nop dword ptr [rax + rax]  [0f 1f 44 00 00]
    // ASM: nop dword ptr [rax + rax] (Address: 0x7357)

    // 0x735c: jmp 7086h  [e9 25 fd ff ff]
    goto label_0x7086;
    // >>> Control flow: Jump to 0x7086


label_0x7361:
    // ============= Basic Block 10 =============
    // Address Range: 0x7361 - 0x736b
    // Instructions: 4

    // 0x7361: mov eax, 80040111h  [b8 11 01 04 80]
    reg_eax = 2147746065;

    // 0x7366: test edi, edi  [85 ff]
    // Test: reg_edi & reg_edi

    // 0x7368: cmove edi, eax  [0f 44 f8]
    // ASM: cmove edi, eax (Address: 0x7368)

    // 0x736b: jmp 70b6h  [e9 46 fd ff ff]
    goto label_0x70b6;
    // >>> Control flow: Jump to 0x70b6


label_0x7243:
    // ============= Basic Block 11 =============
    // Address Range: 0x7243 - 0x728a
    // Instructions: 17

    // 0x7243: xor ecx, ecx  [33 c9]
    reg_ecx ^= reg_ecx;

    // 0x7245: call qword ptr [rip + 8f0ch]  [48 ff 15 0c 8f 00 00]
    // Function call
    // >>> Function call detected

    // 0x724c: nop dword ptr [rax + rax]  [0f 1f 44 00 00]
    // ASM: nop dword ptr [rax + rax] (Address: 0x724c)

    // 0x7251: mov rcx, rax  [48 8b c8]
    reg_rcx = reg_rax;

    // 0x7254: call qword ptr [rip + 8f2dh]  [48 ff 15 2d 8f 00 00]
    // Function call
    // >>> Function call detected

    // 0x725b: nop dword ptr [rax + rax]  [0f 1f 44 00 00]
    // ASM: nop dword ptr [rax + rax] (Address: 0x725b)

    // 0x7260: call qword ptr [rip + 8f11h]  [48 ff 15 11 8f 00 00]
    // Function call
    // >>> Function call detected

    // 0x7267: nop dword ptr [rax + rax]  [0f 1f 44 00 00]
    // ASM: nop dword ptr [rax + rax] (Address: 0x7267)

    // 0x726c: mov dword ptr [rbp + 18h], eax  [89 45 18]
    unknown_operand = reg_eax;

    // 0x726f: mov qword ptr [r15], rbp  [49 89 2f]
    unknown_operand = reg_rbp;

    // 0x7272: mov rcx, qword ptr [rip + 0edcfh]  [48 8b 0d cf ed 00 00]
    reg_rcx = unknown_operand;

    // 0x7279: cmp rcx, r12  [49 3b cc]
    // Compare: reg_rcx vs reg_r12

    // 0x727c: je 7288h  [74 0a]
    if (zero_flag) goto label_0x7288;
    // >>> Control flow: Jump to 0x7288

    // 0x727e: test byte ptr [rcx + 1ch], 4  [f6 41 1c 04]
    // Test: unknown_operand & 4

    // 0x7282: jne 7370h  [0f 85 e8 00 00 00]
    if (!zero_flag) goto label_0x7370;
    // >>> Control flow: Jump to 0x7370

    // 0x7288: mov edi, ebx  [8b fb]
    reg_edi = reg_ebx;

    // 0x728a: jmp 7139h  [e9 aa fe ff ff]
    goto label_0x7139;
    // >>> Control flow: Jump to 0x7139


label_0x7309:
    // ============= Basic Block 12 =============
    // Address Range: 0x7309 - 0x7311
    // Instructions: 3

    // 0x7309: mov edx, 15h  [ba 15 00 00 00]
    reg_edx = 21;

    // 0x730e: mov r9d, eax  [44 8b c8]
    reg_r9d = reg_eax;

    // 0x7311: jmp 71ddh  [e9 c7 fe ff ff]
    goto label_0x71dd;
    // >>> Control flow: Jump to 0x71dd


label_0x71fb:
    // ============= Basic Block 13 =============
    // Address Range: 0x71fb - 0x721f
    // Instructions: 10

    // 0x71fb: test rcx, rcx  [48 85 c9]
    // Test: reg_rcx & reg_rcx

    // 0x71fe: je 7210h  [74 10]
    if (zero_flag) goto label_0x7210;
    // >>> Control flow: Jump to 0x7210

    // 0x7200: mov rax, qword ptr [rcx]  [48 8b 01]
    reg_rax = unknown_operand;

    // 0x7203: mov edx, 1  [ba 01 00 00 00]
    reg_edx = 1;

    // 0x7208: mov rax, qword ptr [rax]  [48 8b 00]
    reg_rax = unknown_operand;

    // 0x720b: call 0e010h  [e8 00 6e 00 00]
    call_function_0xe010();
    // >>> Function call detected

    // 0x7210: mov rcx, rbp  [48 8b cd]
    reg_rcx = reg_rbp;

    // 0x7213: call qword ptr [rip + 11dfeh]  [48 ff 15 fe 1d 01 00]
    // Function call
    // >>> Function call detected

    // 0x721a: nop dword ptr [rax + rax]  [0f 1f 44 00 00]
    // ASM: nop dword ptr [rax + rax] (Address: 0x721a)

    // 0x721f: jmp 7139h  [e9 15 ff ff ff]
    goto label_0x7139;
    // >>> Control flow: Jump to 0x7139


label_0x7224:
    // ============= Basic Block 14 =============
    // Address Range: 0x7224 - 0x7230
    // Instructions: 4

    // 0x7224: mov rax, qword ptr [rcx]  [48 8b 01]
    reg_rax = unknown_operand;

    // 0x7227: mov rax, qword ptr [rax + 10h]  [48 8b 40 10]
    reg_rax = unknown_operand;

    // 0x722b: call 0e010h  [e8 e0 6d 00 00]
    call_function_0xe010();
    // >>> Function call detected

    // 0x7230: jmp 7129h  [e9 f4 fe ff ff]
    goto label_0x7129;
    // >>> Control flow: Jump to 0x7129


label_0x73ad:
    // ============= Basic Block 15 =============
    // Address Range: 0x73ad - 0x73d1
    // Instructions: 8

    // 0x73ad: test byte ptr [rcx + 1ch], 1  [f6 41 1c 01]
    // Test: unknown_operand & 1

    // 0x73b1: je 723eh  [0f 84 87 fe ff ff]
    if (zero_flag) goto label_0x723e;
    // >>> Control flow: Jump to 0x723e

    // 0x73b7: mov edx, 10h  [ba 10 00 00 00]
    reg_edx = 16;

    // 0x73bc: lea r8, [rip + 93edh]  [4c 8d 05 ed 93 00 00]
    reg_r8 = &unknown_operand;

    // 0x73c3: mov rcx, qword ptr [rcx + 10h]  [48 8b 49 10]
    reg_rcx = unknown_operand;

    // 0x73c7: call 928ch  [e8 c0 1e 00 00]
    call_function_0x928c();
    // >>> Function call detected

    // 0x73cc: mov rbx, qword ptr [rsp + 60h]  [48 8b 5c 24 60]
    reg_rbx = unknown_operand;

    // 0x73d1: jmp 723eh  [e9 68 fe ff ff]
    goto label_0x723e;
    // >>> Control flow: Jump to 0x723e


label_0x738d:
    // ============= Basic Block 16 =============
    // Address Range: 0x738d - 0x73a8
    // Instructions: 7

    // 0x738d: test byte ptr [rcx + 1ch], 1  [f6 41 1c 01]
    // Test: unknown_operand & 1

    // 0x7391: je 719ah  [0f 84 03 fe ff ff]
    if (zero_flag) goto label_0x719a;
    // >>> Control flow: Jump to 0x719a

    // 0x7397: mov r9, rdi  [4c 8b cf]
    reg_r9 = reg_rdi;

    // 0x739a: mov rcx, qword ptr [rcx + 10h]  [48 8b 49 10]
    reg_rcx = unknown_operand;

    // 0x739e: call 0b7fch  [e8 59 44 00 00]
    call_function_0xb7fc();
    // >>> Function call detected

    // 0x73a3: mov rbx, qword ptr [rsp + 60h]  [48 8b 5c 24 60]
    reg_rbx = unknown_operand;

    // 0x73a8: jmp 719ah  [e9 ed fd ff ff]
    goto label_0x719a;
    // >>> Control flow: Jump to 0x719a


label_0x7370:
    // ============= Basic Block 17 =============
    // Address Range: 0x7370 - 0x7388
    // Instructions: 6

    // 0x7370: mov edx, 16h  [ba 16 00 00 00]
    reg_edx = 22;

    // 0x7375: mov r9, rbp  [4c 8b cd]
    reg_r9 = reg_rbp;

    // 0x7378: lea r8, [rip + 9431h]  [4c 8d 05 31 94 00 00]
    reg_r8 = &unknown_operand;

    // 0x737f: mov rcx, qword ptr [rcx + 10h]  [48 8b 49 10]
    reg_rcx = unknown_operand;

    // 0x7383: call 0b848h  [e8 c0 44 00 00]
    call_function_0xb848();
    // >>> Function call detected

    // 0x7388: jmp 7288h  [e9 fb fe ff ff]
    goto label_0x7288;
    // >>> Control flow: Jump to 0x7288


}

// ============ DISCOVERED FUNCTIONS ============

// ============================================
// Complete implementation of sub_2650
// Original Address: 0x2650
// Total Instructions: 10
// Basic Blocks: 1
// Register Usage: rax, rcx, rdx, rsp
// ============================================
uint64_t sub_2650(uint64_t param2) {
    // CPU Register simulation
    uint64_t reg_rcx = 0;  // Counter register
    uint64_t reg_rax = 0;  // Accumulator register
    uint64_t reg_rsp = 0;  // Stack pointer
    uint64_t reg_rdx = 0;  // Data register

    // CPU Flags simulation
    bool zero_flag = false;
    bool carry_flag = false;
    bool sign_flag = false;
    bool overflow_flag = false;

    // ============= Basic Block 1 =============
    // Address Range: 0x2650 - 0x2672
    // Instructions: 10

    // 0x2650: sub rsp, 28h  [48 83 ec 28]
    reg_rsp -= 40;

    // 0x2654: mov rax, qword ptr [rcx]  [48 8b 01]
    reg_rax = unknown_operand;

    // 0x2657: mov qword ptr [rcx], rdx  [48 89 11]
    unknown_operand = reg_rdx;

    // 0x265a: test rax, rax  [48 85 c0]
    // Test: reg_rax & reg_rax

    // 0x265d: je 266eh  [74 0f]
    if (zero_flag) goto label_0x266e;
    // >>> Control flow: Jump to 0x266e

    // 0x265f: mov rcx, rax  [48 8b c8]
    reg_rcx = reg_rax;

    // 0x2662: call qword ptr [rip + 169afh]  [48 ff 15 af 69 01 00]
    // Function call
    // >>> Function call detected

    // 0x2669: nop dword ptr [rax + rax]  [0f 1f 44 00 00]
    // ASM: nop dword ptr [rax + rax] (Address: 0x2669)

    // 0x266e: add rsp, 28h  [48 83 c4 28]
    reg_rsp += 40;

    // 0x2672: ret   [c3]
    return result;
    // >>> Function return


}

// ============================================
// Complete implementation of sub_1120
// Original Address: 0x1120
// Total Instructions: 13
// Basic Blocks: 2
// Register Usage: eax, rax, rcx, rsp
// ============================================
uint64_t sub_1120(void) {
    // CPU Register simulation
    uint64_t reg_rcx = 0;  // Counter register
    uint64_t reg_rax = 0;  // Accumulator register
    uint64_t reg_rsp = 0;  // Stack pointer

    // CPU Flags simulation
    bool zero_flag = false;
    bool carry_flag = false;
    bool sign_flag = false;
    bool overflow_flag = false;

    // ============= Basic Block 1 =============
    // Address Range: 0x1120 - 0x1134
    // Instructions: 5

    // 0x1120: sub rsp, 28h  [48 83 ec 28]
    reg_rsp -= 40;

    // 0x1124: call 3de4h  [e8 bb 2c 00 00]
    call_function_0x3de4();
    // >>> Function call detected

    // 0x1129: lea rcx, [rip + 0cd10h]  [48 8d 0d 10 cd 00 00]
    reg_rcx = &unknown_operand;

    // 0x1130: add rsp, 28h  [48 83 c4 28]
    reg_rsp += 40;

    // 0x1134: jmp 9960h  [e9 27 88 00 00]
    goto label_0x9960;
    // >>> Control flow: Jump to 0x9960


label_0x9960:
    // ============= Basic Block 2 =============
    // Address Range: 0x9960 - 0x9976
    // Instructions: 8

    // 0x9960: sub rsp, 28h  [48 83 ec 28]
    reg_rsp -= 40;

    // 0x9964: call 98c8h  [e8 5f ff ff ff]
    call_function_0x98c8();
    // >>> Function call detected

    // 0x9969: neg rax  [48 f7 d8]
    // ASM: neg rax (Address: 0x9969)

    // 0x996c: sbb eax, eax  [1b c0]
    // ASM: sbb eax, eax (Address: 0x996c)

    // 0x996e: neg eax  [f7 d8]
    // ASM: neg eax (Address: 0x996e)

    // 0x9970: dec eax  [ff c8]
    reg_eax--;

    // 0x9972: add rsp, 28h  [48 83 c4 28]
    reg_rsp += 40;

    // 0x9976: ret   [c3]
    return result;
    // >>> Function return


}

// ============================================
// Complete implementation of sub_381e
// Original Address: 0x381e
// Total Instructions: 14
// Basic Blocks: 1
// Register Usage: rax, rbx, rcx, rsp
// ============================================
uint64_t sub_381e(uint64_t param1) {
    // CPU Register simulation
    uint64_t reg_rbx = 0;  // Base register
    uint64_t reg_rax = 0;  // Accumulator register
    uint64_t reg_rcx = 0;  // Counter register
    uint64_t reg_rsp = 0;  // Stack pointer

    // CPU Flags simulation
    bool zero_flag = false;
    bool carry_flag = false;
    bool sign_flag = false;
    bool overflow_flag = false;

    // ============= Basic Block 1 =============
    // Address Range: 0x381e - 0x3850
    // Instructions: 14

    // 0x381e: sub rsp, 30h  [48 83 ec 30]
    reg_rsp -= 48;

    // 0x3822: mov rbx, rcx  [48 8b d9]
    reg_rbx = reg_rcx;

    // 0x3825: and dword ptr [rsp + 20h], 0  [83 64 24 20 00]
    unknown_operand &= 0;

    // 0x382a: call 8798h  [e8 69 4f 00 00]
    call_function_0x8798();
    // >>> Function call detected

    // 0x382f: mov dword ptr [rsp + 20h], 1  [c7 44 24 20 01 00 00 00]
    unknown_operand = 1;

    // 0x3837: mov rcx, qword ptr [rsp + 38h]  [48 8b 4c 24 38]
    reg_rcx = unknown_operand;

    // 0x383c: cmp qword ptr [rbx], 0  [48 83 3b 00]
    // Compare: unknown_operand vs 0

    // 0x3840: jne 3848h  [75 06]
    if (!zero_flag) goto label_0x3848;
    // >>> Control flow: Jump to 0x3848

    // 0x3842: call 0c63ch  [e8 f5 8d 00 00]
    call_function_0xc63c();
    // >>> Function call detected

    // 0x3847: int3   [cc]
    // ASM: int3  (Address: 0x3847)

    // 0x3848: mov rax, rbx  [48 8b c3]
    reg_rax = reg_rbx;

    // 0x384b: add rsp, 30h  [48 83 c4 30]
    reg_rsp += 48;

    // 0x384f: pop rbx  [5b]
    // POP reg_rbx

    // 0x3850: ret   [c3]
    return result;
    // >>> Function return


}

// ============================================
// Complete implementation of sub_3818
// Original Address: 0x3818
// Total Instructions: 16
// Basic Blocks: 1
// Register Usage: rax, rbx, rcx, rsp
// ============================================
uint64_t sub_3818(uint64_t param1) {
    // CPU Register simulation
    uint64_t reg_rbx = 0;  // Base register
    uint64_t reg_rax = 0;  // Accumulator register
    uint64_t reg_rcx = 0;  // Counter register
    uint64_t reg_rsp = 0;  // Stack pointer

    // CPU Flags simulation
    bool zero_flag = false;
    bool carry_flag = false;
    bool sign_flag = false;
    bool overflow_flag = false;

    // ============= Basic Block 1 =============
    // Address Range: 0x3818 - 0x3850
    // Instructions: 16

    // 0x3818: mov qword ptr [rsp + 8], rcx  [48 89 4c 24 08]
    unknown_operand = reg_rcx;

    // 0x381d: push rbx  [53]
    // PUSH reg_rbx

    // 0x381e: sub rsp, 30h  [48 83 ec 30]
    reg_rsp -= 48;

    // 0x3822: mov rbx, rcx  [48 8b d9]
    reg_rbx = reg_rcx;

    // 0x3825: and dword ptr [rsp + 20h], 0  [83 64 24 20 00]
    unknown_operand &= 0;

    // 0x382a: call 8798h  [e8 69 4f 00 00]
    call_function_0x8798();
    // >>> Function call detected

    // 0x382f: mov dword ptr [rsp + 20h], 1  [c7 44 24 20 01 00 00 00]
    unknown_operand = 1;

    // 0x3837: mov rcx, qword ptr [rsp + 38h]  [48 8b 4c 24 38]
    reg_rcx = unknown_operand;

    // 0x383c: cmp qword ptr [rbx], 0  [48 83 3b 00]
    // Compare: unknown_operand vs 0

    // 0x3840: jne 3848h  [75 06]
    if (!zero_flag) goto label_0x3848;
    // >>> Control flow: Jump to 0x3848

    // 0x3842: call 0c63ch  [e8 f5 8d 00 00]
    call_function_0xc63c();
    // >>> Function call detected

    // 0x3847: int3   [cc]
    // ASM: int3  (Address: 0x3847)

    // 0x3848: mov rax, rbx  [48 8b c3]
    reg_rax = reg_rbx;

    // 0x384b: add rsp, 30h  [48 83 c4 30]
    reg_rsp += 48;

    // 0x384f: pop rbx  [5b]
    // POP reg_rbx

    // 0x3850: ret   [c3]
    return result;
    // >>> Function return


}

// ============================================
// Complete implementation of sub_3a32
// Original Address: 0x3a32
// Total Instructions: 19
// Basic Blocks: 2
// Register Usage: cl, dil, dl, r8, rax, rbx, rdi, rsp
// ============================================
uint64_t sub_3a32(uint64_t param3) {
    // CPU Register simulation
    uint64_t reg_rdx = 0;  // Data register
    uint64_t reg_rsp = 0;  // Stack pointer
    uint64_t reg_rax = 0;  // Accumulator register
    uint64_t reg_dil = 0;
    uint64_t reg_rdi = 0;  // Destination index
    uint64_t reg_rbx = 0;  // Base register
    uint64_t reg_rcx = 0;  // Counter register
    uint64_t reg_r8 = 0;  // General purpose register

    // CPU Flags simulation
    bool zero_flag = false;
    bool carry_flag = false;
    bool sign_flag = false;
    bool overflow_flag = false;

    // ============= Basic Block 1 =============
    // Address Range: 0x3a32 - 0x3a6b
    // Instructions: 15

    // 0x3a32: sub rsp, 20h  [48 83 ec 20]
    reg_rsp -= 32;

    // 0x3a36: mov rbx, qword ptr [rip + 13433h]  [48 8b 1d 33 34 01 00]
    reg_rbx = unknown_operand;

    // 0x3a3d: mov dil, dl  [40 8a fa]
    reg_dil = reg_dl;

    // 0x3a40: mov rax, qword ptr [rip + 13431h]  [48 8b 05 31 34 01 00]
    reg_rax = unknown_operand;

    // 0x3a47: cmp rbx, rax  [48 3b d8]
    // Compare: reg_rbx vs reg_rax

    // 0x3a4a: jae 3a6dh  [73 21]
    // ASM: jae 3a6dh (Address: 0x3a4a)
    // >>> Control flow: Jump to 0x3a6d

    // 0x3a4c: mov r8, qword ptr [rbx]  [4c 8b 03]
    reg_r8 = unknown_operand;

    // 0x3a4f: test r8, r8  [4d 85 c0]
    // Test: reg_r8 & reg_r8

    // 0x3a52: je 3a67h  [74 13]
    if (zero_flag) goto label_0x3a67;
    // >>> Control flow: Jump to 0x3a67

    // 0x3a54: mov rax, qword ptr [r8 + 40h]  [49 8b 40 40]
    reg_rax = unknown_operand;

    // 0x3a58: mov cl, dil  [40 8a cf]
    reg_cl = reg_dil;

    // 0x3a5b: call 0e010h  [e8 b0 a5 00 00]
    call_function_0xe010();
    // >>> Function call detected

    // 0x3a60: mov rax, qword ptr [rip + 13411h]  [48 8b 05 11 34 01 00]
    reg_rax = unknown_operand;

    // 0x3a67: add rbx, 8  [48 83 c3 08]
    reg_rbx += 8;

    // 0x3a6b: jmp 3a47h  [eb da]
    goto label_0x3a47;
    // >>> Control flow: Jump to 0x3a47


label_0x3a6d:
    // ============= Basic Block 2 =============
    // Address Range: 0x3a6d - 0x3a77
    // Instructions: 4

    // 0x3a6d: mov rbx, qword ptr [rsp + 30h]  [48 8b 5c 24 30]
    reg_rbx = unknown_operand;

    // 0x3a72: add rsp, 20h  [48 83 c4 20]
    reg_rsp += 32;

    // 0x3a76: pop rdi  [5f]
    // POP reg_rdi

    // 0x3a77: ret   [c3]
    return result;
    // >>> Function return


}

// ============================================
// Complete implementation of sub_3a2c
// Original Address: 0x3a2c
// Total Instructions: 21
// Basic Blocks: 2
// Register Usage: cl, dil, dl, r8, rax, rbx, rdi, rsp
// ============================================
uint64_t sub_3a2c(uint64_t param3) {
    // CPU Register simulation
    uint64_t reg_rdx = 0;  // Data register
    uint64_t reg_rsp = 0;  // Stack pointer
    uint64_t reg_rax = 0;  // Accumulator register
    uint64_t reg_dil = 0;
    uint64_t reg_rdi = 0;  // Destination index
    uint64_t reg_rbx = 0;  // Base register
    uint64_t reg_rcx = 0;  // Counter register
    uint64_t reg_r8 = 0;  // General purpose register

    // CPU Flags simulation
    bool zero_flag = false;
    bool carry_flag = false;
    bool sign_flag = false;
    bool overflow_flag = false;

    // ============= Basic Block 1 =============
    // Address Range: 0x3a2c - 0x3a6b
    // Instructions: 17

    // 0x3a2c: mov qword ptr [rsp + 8], rbx  [48 89 5c 24 08]
    unknown_operand = reg_rbx;

    // 0x3a31: push rdi  [57]
    // PUSH reg_rdi

    // 0x3a32: sub rsp, 20h  [48 83 ec 20]
    reg_rsp -= 32;

    // 0x3a36: mov rbx, qword ptr [rip + 13433h]  [48 8b 1d 33 34 01 00]
    reg_rbx = unknown_operand;

    // 0x3a3d: mov dil, dl  [40 8a fa]
    reg_dil = reg_dl;

    // 0x3a40: mov rax, qword ptr [rip + 13431h]  [48 8b 05 31 34 01 00]
    reg_rax = unknown_operand;

    // 0x3a47: cmp rbx, rax  [48 3b d8]
    // Compare: reg_rbx vs reg_rax

    // 0x3a4a: jae 3a6dh  [73 21]
    // ASM: jae 3a6dh (Address: 0x3a4a)
    // >>> Control flow: Jump to 0x3a6d

    // 0x3a4c: mov r8, qword ptr [rbx]  [4c 8b 03]
    reg_r8 = unknown_operand;

    // 0x3a4f: test r8, r8  [4d 85 c0]
    // Test: reg_r8 & reg_r8

    // 0x3a52: je 3a67h  [74 13]
    if (zero_flag) goto label_0x3a67;
    // >>> Control flow: Jump to 0x3a67

    // 0x3a54: mov rax, qword ptr [r8 + 40h]  [49 8b 40 40]
    reg_rax = unknown_operand;

    // 0x3a58: mov cl, dil  [40 8a cf]
    reg_cl = reg_dil;

    // 0x3a5b: call 0e010h  [e8 b0 a5 00 00]
    call_function_0xe010();
    // >>> Function call detected

    // 0x3a60: mov rax, qword ptr [rip + 13411h]  [48 8b 05 11 34 01 00]
    reg_rax = unknown_operand;

    // 0x3a67: add rbx, 8  [48 83 c3 08]
    reg_rbx += 8;

    // 0x3a6b: jmp 3a47h  [eb da]
    goto label_0x3a47;
    // >>> Control flow: Jump to 0x3a47


label_0x3a6d:
    // ============= Basic Block 2 =============
    // Address Range: 0x3a6d - 0x3a77
    // Instructions: 4

    // 0x3a6d: mov rbx, qword ptr [rsp + 30h]  [48 8b 5c 24 30]
    reg_rbx = unknown_operand;

    // 0x3a72: add rsp, 20h  [48 83 c4 20]
    reg_rsp += 32;

    // 0x3a76: pop rdi  [5f]
    // POP reg_rdi

    // 0x3a77: ret   [c3]
    return result;
    // >>> Function return


}

// ============================================
// Complete implementation of sub_1140
// Original Address: 0x1140
// Total Instructions: 18
// Basic Blocks: 2
// Register Usage: dl, eax, rax, rcx, rsp
// ============================================
uint64_t sub_1140(void) {
    // CPU Register simulation
    uint64_t reg_rdx = 0;  // Data register
    uint64_t reg_rax = 0;  // Accumulator register
    uint64_t reg_rcx = 0;  // Counter register
    uint64_t reg_rsp = 0;  // Stack pointer

    // CPU Flags simulation
    bool zero_flag = false;
    bool carry_flag = false;
    bool sign_flag = false;
    bool overflow_flag = false;

    // ============= Basic Block 1 =============
    // Address Range: 0x1140 - 0x116a
    // Instructions: 10

    // 0x1140: sub rsp, 28h  [48 83 ec 28]
    reg_rsp -= 40;

    // 0x1144: call 3a80h  [e8 37 29 00 00]
    call_function_0x3a80();
    // >>> Function call detected

    // 0x1149: mov dl, 1  [b2 01]
    reg_dl = 1;

    // 0x114b: call 3a2ch  [e8 dc 28 00 00]
    call_function_0x3a2c();
    // >>> Function call detected

    // 0x1150: nop   [90]
    // ASM: nop  (Address: 0x1150)

    // 0x1151: lea rax, [rip + 0dfd8h]  [48 8d 05 d8 df 00 00]
    reg_rax = &unknown_operand;

    // 0x1158: mov qword ptr [rip + 15cb1h], rax  [48 89 05 b1 5c 01 00]
    unknown_operand = reg_rax;

    // 0x115f: lea rcx, [rip + 0cc6ah]  [48 8d 0d 6a cc 00 00]
    reg_rcx = &unknown_operand;

    // 0x1166: add rsp, 28h  [48 83 c4 28]
    reg_rsp += 40;

    // 0x116a: jmp 9960h  [e9 f1 87 00 00]
    goto label_0x9960;
    // >>> Control flow: Jump to 0x9960


label_0x9960:
    // ============= Basic Block 2 =============
    // Address Range: 0x9960 - 0x9976
    // Instructions: 8

    // 0x9960: sub rsp, 28h  [48 83 ec 28]
    reg_rsp -= 40;

    // 0x9964: call 98c8h  [e8 5f ff ff ff]
    call_function_0x98c8();
    // >>> Function call detected

    // 0x9969: neg rax  [48 f7 d8]
    // ASM: neg rax (Address: 0x9969)

    // 0x996c: sbb eax, eax  [1b c0]
    // ASM: sbb eax, eax (Address: 0x996c)

    // 0x996e: neg eax  [f7 d8]
    // ASM: neg eax (Address: 0x996e)

    // 0x9970: dec eax  [ff c8]
    reg_eax--;

    // 0x9972: add rsp, 28h  [48 83 c4 28]
    reg_rsp += 40;

    // 0x9976: ret   [c3]
    return result;
    // >>> Function return


}

// ============================================
// Complete implementation of sub_395e
// Original Address: 0x395e
// Total Instructions: 20
// Basic Blocks: 3
// Register Usage: edx, rbx, rcx, rsp
// ============================================
uint64_t sub_395e(uint64_t param1) {
    // CPU Register simulation
    uint64_t reg_rdx = 0;  // Data register
    uint64_t reg_rcx = 0;  // Counter register
    uint64_t reg_rbx = 0;  // Base register
    uint64_t reg_rsp = 0;  // Stack pointer

    // CPU Flags simulation
    bool zero_flag = false;
    bool carry_flag = false;
    bool sign_flag = false;
    bool overflow_flag = false;

    // ============= Basic Block 1 =============
    // Address Range: 0x395e - 0x397b
    // Instructions: 11

    // 0x395e: sub rsp, 20h  [48 83 ec 20]
    reg_rsp -= 32;

    // 0x3962: mov rbx, rcx  [48 8b d9]
    reg_rbx = reg_rcx;

    // 0x3965: mov rcx, qword ptr [rcx + 8]  [48 8b 49 08]
    reg_rcx = unknown_operand;

    // 0x3969: test rcx, rcx  [48 85 c9]
    // Test: reg_rcx & reg_rcx

    // 0x396c: jne 397dh  [75 0f]
    if (!zero_flag) goto label_0x397d;
    // >>> Control flow: Jump to 0x397d

    // 0x396e: mov rcx, qword ptr [rbx]  [48 8b 0b]
    reg_rcx = unknown_operand;

    // 0x3971: test rcx, rcx  [48 85 c9]
    // Test: reg_rcx & reg_rcx

    // 0x3974: jne 3990h  [75 1a]
    if (!zero_flag) goto label_0x3990;
    // >>> Control flow: Jump to 0x3990

    // 0x3976: add rsp, 20h  [48 83 c4 20]
    reg_rsp += 32;

    // 0x397a: pop rbx  [5b]
    // POP reg_rbx

    // 0x397b: ret   [c3]
    return result;
    // >>> Function return


label_0x397d:
    // ============= Basic Block 2 =============
    // Address Range: 0x397d - 0x398e
    // Instructions: 4

    // 0x397d: call qword ptr [rip + 156c4h]  [48 ff 15 c4 56 01 00]
    // Function call
    // >>> Function call detected

    // 0x3984: nop dword ptr [rax + rax]  [0f 1f 44 00 00]
    // ASM: nop dword ptr [rax + rax] (Address: 0x3984)

    // 0x3989: and qword ptr [rbx + 8], 0  [48 83 63 08 00]
    unknown_operand &= 0;

    // 0x398e: jmp 396eh  [eb de]
    goto label_0x396e;
    // >>> Control flow: Jump to 0x396e


label_0x3990:
    // ============= Basic Block 3 =============
    // Address Range: 0x3990 - 0x39a2
    // Instructions: 5

    // 0x3990: xor edx, edx  [33 d2]
    reg_edx ^= reg_edx;

    // 0x3992: call qword ptr [rip + 1569fh]  [48 ff 15 9f 56 01 00]
    // Function call
    // >>> Function call detected

    // 0x3999: nop dword ptr [rax + rax]  [0f 1f 44 00 00]
    // ASM: nop dword ptr [rax + rax] (Address: 0x3999)

    // 0x399e: and qword ptr [rbx], 0  [48 83 23 00]
    unknown_operand &= 0;

    // 0x39a2: jmp 3976h  [eb d2]
    goto label_0x3976;
    // >>> Control flow: Jump to 0x3976


}

// ============================================
// Complete implementation of sub_1842
// Original Address: 0x1842
// Total Instructions: 21
// Basic Blocks: 2
// Register Usage: edx, r8, r9, rax, rbx, rcx, rsp
// ============================================
uint64_t sub_1842(uint64_t param1) {
    // CPU Register simulation
    uint64_t reg_rdx = 0;  // Data register
    uint64_t reg_rsp = 0;  // Stack pointer
    uint64_t reg_rax = 0;  // Accumulator register
    uint64_t reg_r9 = 0;  // General purpose register
    uint64_t reg_rbx = 0;  // Base register
    uint64_t reg_rcx = 0;  // Counter register
    uint64_t reg_r8 = 0;  // General purpose register

    // CPU Flags simulation
    bool zero_flag = false;
    bool carry_flag = false;
    bool sign_flag = false;
    bool overflow_flag = false;

    // ============= Basic Block 1 =============
    // Address Range: 0x1842 - 0x1874
    // Instructions: 15

    // 0x1842: sub rsp, 20h  [48 83 ec 20]
    reg_rsp -= 32;

    // 0x1846: mov rbx, rcx  [48 8b d9]
    reg_rbx = reg_rcx;

    // 0x1849: mov rcx, qword ptr [rip + 147f8h]  [48 8b 0d f8 47 01 00]
    reg_rcx = unknown_operand;

    // 0x1850: lea rax, [rip + 147f1h]  [48 8d 05 f1 47 01 00]
    reg_rax = &unknown_operand;

    // 0x1857: cmp rcx, rax  [48 3b c8]
    // Compare: reg_rcx vs reg_rax

    // 0x185a: je 1862h  [74 06]
    if (zero_flag) goto label_0x1862;
    // >>> Control flow: Jump to 0x1862

    // 0x185c: test byte ptr [rcx + 1ch], 4  [f6 41 1c 04]
    // Test: unknown_operand & 4

    // 0x1860: jne 1876h  [75 14]
    if (!zero_flag) goto label_0x1876;
    // >>> Control flow: Jump to 0x1876

    // 0x1862: test rbx, rbx  [48 85 db]
    // Test: reg_rbx & reg_rbx

    // 0x1865: je 186fh  [74 08]
    if (zero_flag) goto label_0x186f;
    // >>> Control flow: Jump to 0x186f

    // 0x1867: mov rcx, rbx  [48 8b cb]
    reg_rcx = reg_rbx;

    // 0x186a: call 18a0h  [e8 31 00 00 00]
    call_function_0x18a0();
    // >>> Function call detected

    // 0x186f: add rsp, 20h  [48 83 c4 20]
    reg_rsp += 32;

    // 0x1873: pop rbx  [5b]
    // POP reg_rbx

    // 0x1874: ret   [c3]
    return result;
    // >>> Function return


label_0x1876:
    // ============= Basic Block 2 =============
    // Address Range: 0x1876 - 0x188e
    // Instructions: 6

    // 0x1876: mov rcx, qword ptr [rcx + 10h]  [48 8b 49 10]
    reg_rcx = unknown_operand;

    // 0x187a: lea r8, [rip + 0ef2fh]  [4c 8d 05 2f ef 00 00]
    reg_r8 = &unknown_operand;

    // 0x1881: mov edx, 17h  [ba 17 00 00 00]
    reg_edx = 23;

    // 0x1886: mov r9, rbx  [4c 8b cb]
    reg_r9 = reg_rbx;

    // 0x1889: call 0b848h  [e8 ba 9f 00 00]
    call_function_0xb848();
    // >>> Function call detected

    // 0x188e: jmp 1862h  [eb d2]
    goto label_0x1862;
    // >>> Control flow: Jump to 0x1862


}

// ============================================
// Complete implementation of sub_3a82
// Original Address: 0x3a82
// Total Instructions: 23
// Basic Blocks: 2
// Register Usage: eax, rax, rcx, rdi, rsp, xmm0
// ============================================
uint64_t sub_3a82(void) {
    // CPU Register simulation
    uint64_t reg_rsp = 0;  // Stack pointer
    uint64_t reg_rax = 0;  // Accumulator register
    uint64_t reg_rdi = 0;  // Destination index
    uint64_t reg_xmm0 = 0;
    uint64_t reg_rcx = 0;  // Counter register

    // CPU Flags simulation
    bool zero_flag = false;
    bool carry_flag = false;
    bool sign_flag = false;
    bool overflow_flag = false;

    // ============= Basic Block 1 =============
    // Address Range: 0x3a82 - 0x3aea
    // Instructions: 21

    // 0x3a82: sub rsp, 20h  [48 83 ec 20]
    reg_rsp -= 32;

    // 0x3a86: xor eax, eax  [33 c0]
    reg_eax ^= reg_eax;

    // 0x3a88: lea rdi, [rip + 13381h]  [48 8d 3d 81 33 01 00]
    reg_rdi = &unknown_operand;

    // 0x3a8f: and dword ptr [rip + 13383h], eax  [21 05 83 33 01 00]
    unknown_operand &= reg_eax;

    // 0x3a95: lea rcx, [rip + 1338ch]  [48 8d 0d 8c 33 01 00]
    reg_rcx = &unknown_operand;

    // 0x3a9c: and qword ptr [rip + 1337dh], rax  [48 21 05 7d 33 01 00]
    unknown_operand &= reg_rax;

    // 0x3aa3: xorps xmm0, xmm0  [0f 57 c0]
    // ASM: xorps xmm0, xmm0 (Address: 0x3aa3)

    // 0x3aa6: and dword ptr [rip + 13370h], eax  [21 05 70 33 01 00]
    unknown_operand &= reg_eax;

    // 0x3aac: and qword ptr [rip + 1339dh], rax  [48 21 05 9d 33 01 00]
    unknown_operand &= reg_rax;

    // 0x3ab3: movups xmmword ptr [rip + 1336eh], xmm0  [0f 11 05 6e 33 01 00]
    // ASM: movups xmmword ptr [rip + 1336eh], xmm0 (Address: 0x3ab3)

    // 0x3aba: mov qword ptr [rip + 13387h], rax  [48 89 05 87 33 01 00]
    unknown_operand = reg_rax;

    // 0x3ac1: movups xmmword ptr [rip + 13370h], xmm0  [0f 11 05 70 33 01 00]
    // ASM: movups xmmword ptr [rip + 13370h], xmm0 (Address: 0x3ac1)

    // 0x3ac8: mov qword ptr [rip + 133d9h], rdi  [48 89 3d d9 33 01 00]
    unknown_operand = reg_rdi;

    // 0x3acf: call 43c0h  [e8 ec 08 00 00]
    call_function_0x43c0();
    // >>> Function call detected

    // 0x3ad4: test eax, eax  [85 c0]
    // Test: reg_eax & reg_eax

    // 0x3ad6: js 3aech  [78 14]
    // ASM: js 3aech (Address: 0x3ad6)
    // >>> Control flow: Jump to 0x3aec

    // 0x3ad8: mov dword ptr [rip + 13336h], 38h  [c7 05 36 33 01 00 38 00]
    unknown_operand = 56;

    // 0x3ae2: mov rax, rdi  [48 8b c7]
    reg_rax = reg_rdi;

    // 0x3ae5: add rsp, 20h  [48 83 c4 20]
    reg_rsp += 32;

    // 0x3ae9: pop rdi  [5f]
    // POP reg_rdi

    // 0x3aea: ret   [c3]
    return result;
    // >>> Function return


label_0x3aec:
    // ============= Basic Block 2 =============
    // Address Range: 0x3aec - 0x3af3
    // Instructions: 2

    // 0x3aec: mov byte ptr [rip + 133bdh], 1  [c6 05 bd 33 01 00 01]
    unknown_operand = 1;

    // 0x3af3: jmp 3ae2h  [eb ed]
    goto label_0x3ae2;
    // >>> Control flow: Jump to 0x3ae2


}

// ============================================
// Complete implementation of sub_3de4
// Original Address: 0x3de4
// Total Instructions: 23
// Basic Blocks: 2
// Register Usage: eax, rax, rcx, rsp, xmm0
// ============================================
uint64_t sub_3de4(void) {
    // CPU Register simulation
    uint64_t reg_rcx = 0;  // Counter register
    uint64_t reg_rax = 0;  // Accumulator register
    uint64_t reg_xmm0 = 0;
    uint64_t reg_rsp = 0;  // Stack pointer

    // CPU Flags simulation
    bool zero_flag = false;
    bool carry_flag = false;
    bool sign_flag = false;
    bool overflow_flag = false;

    // ============= Basic Block 1 =============
    // Address Range: 0x3de4 - 0x3e57
    // Instructions: 21

    // 0x3de4: sub rsp, 28h  [48 83 ec 28]
    reg_rsp -= 40;

    // 0x3de8: xor eax, eax  [33 c0]
    reg_eax ^= reg_eax;

    // 0x3dea: lea rcx, [rip + 1308fh]  [48 8d 0d 8f 30 01 00]
    reg_rcx = &unknown_operand;

    // 0x3df1: and dword ptr [rip + 13069h], eax  [21 05 69 30 01 00]
    unknown_operand &= reg_eax;

    // 0x3df7: xorps xmm0, xmm0  [0f 57 c0]
    // ASM: xorps xmm0, xmm0 (Address: 0x3df7)

    // 0x3dfa: mov qword ptr [rip + 1309fh], rax  [48 89 05 9f 30 01 00]
    unknown_operand = reg_rax;

    // 0x3e01: lea rax, [rip - 3e08h]  [48 8d 05 f8 c1 ff ff]
    reg_rax = &unknown_operand;

    // 0x3e08: mov qword ptr [rip + 13059h], rax  [48 89 05 59 30 01 00]
    unknown_operand = reg_rax;

    // 0x3e0f: lea rax, [rip + 10132h]  [48 8d 05 32 01 01 00]
    reg_rax = &unknown_operand;

    // 0x3e16: mov qword ptr [rip + 13053h], rax  [48 89 05 53 30 01 00]
    unknown_operand = reg_rax;

    // 0x3e1d: lea rax, [rip + 1012ch]  [48 8d 05 2c 01 01 00]
    reg_rax = &unknown_operand;

    // 0x3e24: mov qword ptr [rip + 1304dh], rax  [48 89 05 4d 30 01 00]
    unknown_operand = reg_rax;

    // 0x3e2b: movups xmmword ptr [rip + 1304eh], xmm0  [0f 11 05 4e 30 01 00]
    // ASM: movups xmmword ptr [rip + 1304eh], xmm0 (Address: 0x3e2b)

    // 0x3e32: movups xmmword ptr [rip + 13057h], xmm0  [0f 11 05 57 30 01 00]
    // ASM: movups xmmword ptr [rip + 13057h], xmm0 (Address: 0x3e32)

    // 0x3e39: call 43c0h  [e8 82 05 00 00]
    call_function_0x43c0();
    // >>> Function call detected

    // 0x3e3e: test eax, eax  [85 c0]
    // Test: reg_eax & reg_eax

    // 0x3e40: js 3e59h  [78 17]
    // ASM: js 3e59h (Address: 0x3e40)
    // >>> Control flow: Jump to 0x3e59

    // 0x3e42: mov dword ptr [rip + 13014h], 48h  [c7 05 14 30 01 00 48 00]
    unknown_operand = 72;

    // 0x3e4c: lea rax, [rip + 1300dh]  [48 8d 05 0d 30 01 00]
    reg_rax = &unknown_operand;

    // 0x3e53: add rsp, 28h  [48 83 c4 28]
    reg_rsp += 40;

    // 0x3e57: ret   [c3]
    return result;
    // >>> Function return


label_0x3e59:
    // ============= Basic Block 2 =============
    // Address Range: 0x3e59 - 0x3e60
    // Instructions: 2

    // 0x3e59: mov byte ptr [rip + 13050h], 1  [c6 05 50 30 01 00 01]
    unknown_operand = 1;

    // 0x3e60: jmp 3e4ch  [eb ea]
    goto label_0x3e4c;
    // >>> Control flow: Jump to 0x3e4c


}

// ============================================
// Complete implementation of sub_1912
// Original Address: 0x1912
// Total Instructions: 24
// Basic Blocks: 1
// Register Usage: ecx, edx, r8d, r9, rax, rbx, rcx, rsp, xmm0
// ============================================
uint64_t sub_1912(uint64_t param1) {
    // CPU Register simulation
    uint64_t reg_rdx = 0;  // Data register
    uint64_t reg_rsp = 0;  // Stack pointer
    uint64_t reg_rax = 0;  // Accumulator register
    uint64_t reg_r9 = 0;  // General purpose register
    uint64_t reg_xmm0 = 0;
    uint64_t reg_rbx = 0;  // Base register
    uint64_t reg_rcx = 0;  // Counter register
    uint64_t reg_r8d = 0;

    // CPU Flags simulation
    bool zero_flag = false;
    bool carry_flag = false;
    bool sign_flag = false;
    bool overflow_flag = false;

    // ============= Basic Block 1 =============
    // Address Range: 0x1912 - 0x1981
    // Instructions: 24

    // 0x1912: sub rsp, 30h  [48 83 ec 30]
    reg_rsp -= 48;

    // 0x1916: mov edx, 8  [ba 08 00 00 00]
    reg_edx = 8;

    // 0x191b: lea rax, [rip + 0d87eh]  [48 8d 05 7e d8 00 00]
    reg_rax = &unknown_operand;

    // 0x1922: mov qword ptr [rcx], rax  [48 89 01]
    unknown_operand = reg_rax;

    // 0x1925: lea r9, [rip + 7484h]  [4c 8d 0d 84 74 00 00]
    reg_r9 = &unknown_operand;

    // 0x192c: mov rbx, rcx  [48 8b d9]
    reg_rbx = reg_rcx;

    // 0x192f: lea rax, [rip + 620ah]  [48 8d 05 0a 62 00 00]
    reg_rax = &unknown_operand;

    // 0x1936: add rcx, 8  [48 83 c1 08]
    reg_rcx += 8;

    // 0x193a: mov qword ptr [rsp + 20h], rax  [48 89 44 24 20]
    unknown_operand = reg_rax;

    // 0x193f: lea r8d, [rdx + 8]  [44 8d 42 08]
    reg_r8d = &unknown_operand;

    // 0x1943: call 9a18h  [e8 d0 80 00 00]
    call_function_0x9a18();
    // >>> Function call detected

    // 0x1948: and qword ptr [rbx + 188h], 0  [48 83 a3 88 01 00 00 00]
    unknown_operand &= 0;

    // 0x1950: lea rax, [rbx + 88h]  [48 8d 83 88 00 00 00]
    reg_rax = &unknown_operand;

    // 0x1957: and qword ptr [rbx + 190h], 0  [48 83 a3 90 01 00 00 00]
    unknown_operand &= 0;

    // 0x195f: mov ecx, 10h  [b9 10 00 00 00]
    reg_ecx = 16;

    // 0x1964: movups xmm0, xmmword ptr [rip + 0ef45h]  [0f 10 05 45 ef 00 00]
    // ASM: movups xmm0, xmmword ptr [rip + 0ef45h] (Address: 0x1964)

    // 0x196b: movdqu xmmword ptr [rax], xmm0  [f3 0f 7f 00]
    // ASM: movdqu xmmword ptr [rax], xmm0 (Address: 0x196b)

    // 0x196f: lea rax, [rax + 10h]  [48 8d 40 10]
    reg_rax = &unknown_operand;

    // 0x1973: sub rcx, 1  [48 83 e9 01]
    reg_rcx -= 1;

    // 0x1977: jne 1964h  [75 eb]
    if (!zero_flag) goto label_0x1964;
    // >>> Control flow: Jump to 0x1964

    // 0x1979: mov rax, rbx  [48 8b c3]
    reg_rax = reg_rbx;

    // 0x197c: add rsp, 30h  [48 83 c4 30]
    reg_rsp += 48;

    // 0x1980: pop rbx  [5b]
    // POP reg_rbx

    // 0x1981: ret   [c3]
    return result;
    // >>> Function return


}

// ============================================
// Complete implementation of sub_39b7
// Original Address: 0x39b7
// Total Instructions: 20
// Basic Blocks: 2
// Register Usage: rbx, rcx, rdi, rdx, rsi, rsp
// ============================================
uint64_t sub_39b7(uint64_t param1, uint64_t param2) {
    // CPU Register simulation
    uint64_t reg_rdx = 0;  // Data register
    uint64_t reg_rsp = 0;  // Stack pointer
    uint64_t reg_rsi = 0;  // Source index
    uint64_t reg_rdi = 0;  // Destination index
    uint64_t reg_rbx = 0;  // Base register
    uint64_t reg_rcx = 0;  // Counter register

    // CPU Flags simulation
    bool zero_flag = false;
    bool carry_flag = false;
    bool sign_flag = false;
    bool overflow_flag = false;

    // ============= Basic Block 1 =============
    // Address Range: 0x39b7 - 0x39db
    // Instructions: 12

    // 0x39b7: sub rsp, 20h  [48 83 ec 20]
    reg_rsp -= 32;

    // 0x39bb: mov rdi, qword ptr [rcx]  [48 8b 39]
    reg_rdi = unknown_operand;

    // 0x39be: mov rsi, rdx  [48 8b f2]
    reg_rsi = reg_rdx;

    // 0x39c1: mov rbx, rcx  [48 8b d9]
    reg_rbx = reg_rcx;

    // 0x39c4: test rdi, rdi  [48 85 ff]
    // Test: reg_rdi & reg_rdi

    // 0x39c7: jne 39ddh  [75 14]
    if (!zero_flag) goto label_0x39dd;
    // >>> Control flow: Jump to 0x39dd

    // 0x39c9: mov qword ptr [rbx], rsi  [48 89 33]
    unknown_operand = reg_rsi;

    // 0x39cc: mov rbx, qword ptr [rsp + 38h]  [48 8b 5c 24 38]
    reg_rbx = unknown_operand;

    // 0x39d1: mov rsi, qword ptr [rsp + 40h]  [48 8b 74 24 40]
    reg_rsi = unknown_operand;

    // 0x39d6: add rsp, 20h  [48 83 c4 20]
    reg_rsp += 32;

    // 0x39da: pop rdi  [5f]
    // POP reg_rdi

    // 0x39db: ret   [c3]
    return result;
    // >>> Function return


label_0x39dd:
    // ============= Basic Block 2 =============
    // Address Range: 0x39dd - 0x3a00
    // Instructions: 8

    // 0x39dd: lea rcx, [rsp + 30h]  [48 8d 4c 24 30]
    reg_rcx = &unknown_operand;

    // 0x39e2: call 0bd74h  [e8 8d 83 00 00]
    call_function_0xbd74();
    // >>> Function call detected

    // 0x39e7: mov rcx, rdi  [48 8b cf]
    reg_rcx = reg_rdi;

    // 0x39ea: call qword ptr [rip + 15627h]  [48 ff 15 27 56 01 00]
    // Function call
    // >>> Function call detected

    // 0x39f1: nop dword ptr [rax + rax]  [0f 1f 44 00 00]
    // ASM: nop dword ptr [rax + rax] (Address: 0x39f1)

    // 0x39f6: lea rcx, [rsp + 30h]  [48 8d 4c 24 30]
    reg_rcx = &unknown_operand;

    // 0x39fb: call 0bdfch  [e8 fc 83 00 00]
    call_function_0xbdfc();
    // >>> Function call detected

    // 0x3a00: jmp 39c9h  [eb c7]
    goto label_0x39c9;
    // >>> Control flow: Jump to 0x39c9


}

// ============================================
// Complete implementation of sub_39ac
// Original Address: 0x39ac
// Total Instructions: 23
// Basic Blocks: 2
// Register Usage: rbx, rcx, rdi, rdx, rsi, rsp
// ============================================
uint64_t sub_39ac(uint64_t param1, uint64_t param2) {
    // CPU Register simulation
    uint64_t reg_rdx = 0;  // Data register
    uint64_t reg_rsp = 0;  // Stack pointer
    uint64_t reg_rsi = 0;  // Source index
    uint64_t reg_rdi = 0;  // Destination index
    uint64_t reg_rbx = 0;  // Base register
    uint64_t reg_rcx = 0;  // Counter register

    // CPU Flags simulation
    bool zero_flag = false;
    bool carry_flag = false;
    bool sign_flag = false;
    bool overflow_flag = false;

    // ============= Basic Block 1 =============
    // Address Range: 0x39ac - 0x39db
    // Instructions: 15

    // 0x39ac: mov qword ptr [rsp + 10h], rbx  [48 89 5c 24 10]
    unknown_operand = reg_rbx;

    // 0x39b1: mov qword ptr [rsp + 18h], rsi  [48 89 74 24 18]
    unknown_operand = reg_rsi;

    // 0x39b6: push rdi  [57]
    // PUSH reg_rdi

    // 0x39b7: sub rsp, 20h  [48 83 ec 20]
    reg_rsp -= 32;

    // 0x39bb: mov rdi, qword ptr [rcx]  [48 8b 39]
    reg_rdi = unknown_operand;

    // 0x39be: mov rsi, rdx  [48 8b f2]
    reg_rsi = reg_rdx;

    // 0x39c1: mov rbx, rcx  [48 8b d9]
    reg_rbx = reg_rcx;

    // 0x39c4: test rdi, rdi  [48 85 ff]
    // Test: reg_rdi & reg_rdi

    // 0x39c7: jne 39ddh  [75 14]
    if (!zero_flag) goto label_0x39dd;
    // >>> Control flow: Jump to 0x39dd

    // 0x39c9: mov qword ptr [rbx], rsi  [48 89 33]
    unknown_operand = reg_rsi;

    // 0x39cc: mov rbx, qword ptr [rsp + 38h]  [48 8b 5c 24 38]
    reg_rbx = unknown_operand;

    // 0x39d1: mov rsi, qword ptr [rsp + 40h]  [48 8b 74 24 40]
    reg_rsi = unknown_operand;

    // 0x39d6: add rsp, 20h  [48 83 c4 20]
    reg_rsp += 32;

    // 0x39da: pop rdi  [5f]
    // POP reg_rdi

    // 0x39db: ret   [c3]
    return result;
    // >>> Function return


label_0x39dd:
    // ============= Basic Block 2 =============
    // Address Range: 0x39dd - 0x3a00
    // Instructions: 8

    // 0x39dd: lea rcx, [rsp + 30h]  [48 8d 4c 24 30]
    reg_rcx = &unknown_operand;

    // 0x39e2: call 0bd74h  [e8 8d 83 00 00]
    call_function_0xbd74();
    // >>> Function call detected

    // 0x39e7: mov rcx, rdi  [48 8b cf]
    reg_rcx = reg_rdi;

    // 0x39ea: call qword ptr [rip + 15627h]  [48 ff 15 27 56 01 00]
    // Function call
    // >>> Function call detected

    // 0x39f1: nop dword ptr [rax + rax]  [0f 1f 44 00 00]
    // ASM: nop dword ptr [rax + rax] (Address: 0x39f1)

    // 0x39f6: lea rcx, [rsp + 30h]  [48 8d 4c 24 30]
    reg_rcx = &unknown_operand;

    // 0x39fb: call 0bdfch  [e8 fc 83 00 00]
    call_function_0xbdfc();
    // >>> Function call detected

    // 0x3a00: jmp 39c9h  [eb c7]
    goto label_0x39c9;
    // >>> Control flow: Jump to 0x39c9


}

// ============================================
// Complete implementation of sub_3c51
// Original Address: 0x3c51
// Total Instructions: 29
// Basic Blocks: 2
// Register Usage: eax, edx, r8, r8d, r9, r9d, r9w, rax, rdx, rsp
// ============================================
uint64_t sub_3c51(uint64_t param2) {
    // CPU Register simulation
    uint64_t reg_rdx = 0;  // Data register
    uint64_t reg_rsp = 0;  // Stack pointer
    uint64_t reg_r9d = 0;
    uint64_t reg_rax = 0;  // Accumulator register
    uint64_t reg_r9w = 0;
    uint64_t reg_r9 = 0;  // General purpose register
    uint64_t reg_r8 = 0;  // General purpose register
    uint64_t reg_r8d = 0;

    // CPU Flags simulation
    bool zero_flag = false;
    bool carry_flag = false;
    bool sign_flag = false;
    bool overflow_flag = false;

    // ============= Basic Block 1 =============
    // Address Range: 0x3c51 - 0x3c7b
    // Instructions: 11

    // 0x3c51: sub rsp, 58h  [48 83 ec 58]
    reg_rsp -= 88;

    // 0x3c55: mov rdx, qword ptr [rsp + 80h]  [48 8b 94 24 80 00 00 00]
    reg_rdx = unknown_operand;

    // 0x3c5d: xor r9d, r9d  [45 33 c9]
    reg_r9d ^= reg_r9d;

    // 0x3c60: test rdx, rdx  [48 85 d2]
    // Test: reg_rdx & reg_rdx

    // 0x3c63: je 3c7dh  [74 18]
    if (zero_flag) goto label_0x3c7d;
    // >>> Control flow: Jump to 0x3c7d

    // 0x3c65: or rax, 0ffffffffffffffffh  [48 83 c8 ff]
    reg_rax |= -1;

    // 0x3c69: inc rax  [48 ff c0]
    reg_rax++;

    // 0x3c6c: cmp word ptr [rdx + rax*2], r9w  [66 44 39 0c 42]
    // Compare: unknown_operand vs reg_r9w

    // 0x3c71: jne 3c69h  [75 f6]
    if (!zero_flag) goto label_0x3c69;
    // >>> Control flow: Jump to 0x3c69

    // 0x3c73: lea rax, [rax*2 + 2]  [48 8d 04 45 02 00 00 00]
    reg_rax = &unknown_operand;

    // 0x3c7b: jmp 3c82h  [eb 05]
    goto label_0x3c82;
    // >>> Control flow: Jump to 0x3c82


label_0x3c7d:
    // ============= Basic Block 2 =============
    // Address Range: 0x3c7d - 0x3cd6
    // Instructions: 18

    // 0x3c7d: mov eax, 0ah  [b8 0a 00 00 00]
    reg_eax = 10;

    // 0x3c82: mov qword ptr [rsp + 40h], r9  [4c 89 4c 24 40]
    unknown_operand = reg_r9;

    // 0x3c87: lea r8, [rip + 0cae2h]  [4c 8d 05 e2 ca 00 00]
    reg_r8 = &unknown_operand;

    // 0x3c8e: mov qword ptr [rsp + 38h], rax  [48 89 44 24 38]
    unknown_operand = reg_rax;

    // 0x3c93: test rdx, rdx  [48 85 d2]
    // Test: reg_rdx & reg_rdx

    // 0x3c96: lea rax, [rsp + 78h]  [48 8d 44 24 78]
    reg_rax = &unknown_operand;

    // 0x3c9b: cmove rdx, r8  [49 0f 44 d0]
    // ASM: cmove rdx, r8 (Address: 0x3c9b)

    // 0x3c9f: mov r8d, 0dh  [41 b8 0d 00 00 00]
    reg_r8d = 13;

    // 0x3ca5: mov qword ptr [rsp + 30h], rdx  [48 89 54 24 30]
    unknown_operand = reg_rdx;

    // 0x3caa: mov r9d, r8d  [45 8b c8]
    reg_r9d = reg_r8d;

    // 0x3cad: mov qword ptr [rsp + 28h], 4  [48 c7 44 24 28 04 00 00]
    unknown_operand = 4;

    // 0x3cb6: lea r8, [rip + 0c823h]  [4c 8d 05 23 c8 00 00]
    reg_r8 = &unknown_operand;

    // 0x3cbd: mov qword ptr [rsp + 20h], rax  [48 89 44 24 20]
    unknown_operand = reg_rax;

    // 0x3cc2: lea edx, [r9 + 1eh]  [41 8d 51 1e]
    reg_edx = &unknown_operand;

    // 0x3cc6: call qword ptr [rip + 0c3abh]  [48 ff 15 ab c3 00 00]
    // Function call
    // >>> Function call detected

    // 0x3ccd: nop dword ptr [rax + rax]  [0f 1f 44 00 00]
    // ASM: nop dword ptr [rax + rax] (Address: 0x3ccd)

    // 0x3cd2: add rsp, 58h  [48 83 c4 58]
    reg_rsp += 88;

    // 0x3cd6: ret   [c3]
    return result;
    // >>> Function return


}

// ============================================
// Complete implementation of sub_3e98
// Original Address: 0x3e98
// Total Instructions: 26
// Basic Blocks: 1
// Register Usage: eax, ebx, ecx, edx, esi, r11, rax, rbp, rbx, rcx, rdi, rsi, rsp
// ============================================
uint64_t sub_3e98(uint64_t param1) {
    // CPU Register simulation
    uint64_t reg_r11 = 0;  // General purpose register
    uint64_t reg_rdx = 0;  // Data register
    uint64_t reg_rbp = 0;  // Base pointer
    uint64_t reg_rsp = 0;  // Stack pointer
    uint64_t reg_rax = 0;  // Accumulator register
    uint64_t reg_rsi = 0;  // Source index
    uint64_t reg_rdi = 0;  // Destination index
    uint64_t reg_rbx = 0;  // Base register
    uint64_t reg_rcx = 0;  // Counter register

    // CPU Flags simulation
    bool zero_flag = false;
    bool carry_flag = false;
    bool sign_flag = false;
    bool overflow_flag = false;

    // ============= Basic Block 1 =============
    // Address Range: 0x3e98 - 0x3ef8
    // Instructions: 26

    // 0x3e98: sub rsp, 60h  [48 83 ec 60]
    reg_rsp -= 96;

    // 0x3e9c: mov rdi, qword ptr [rsp + 98h]  [48 8b bc 24 98 00 00 00]
    reg_rdi = unknown_operand;

    // 0x3ea4: mov esi, edx  [8b f2]
    reg_esi = reg_edx;

    // 0x3ea6: mov qword ptr [rax - 40h], rdi  [48 89 78 c0]
    unknown_operand = reg_rdi;

    // 0x3eaa: mov rbp, rcx  [48 8b e9]
    reg_rbp = reg_rcx;

    // 0x3ead: call 3f00h  [e8 4e 00 00 00]
    call_function_0x3f00();
    // >>> Function call detected

    // 0x3eb2: mov ecx, eax  [8b c8]
    reg_ecx = reg_eax;

    // 0x3eb4: mov dword ptr [rsp + 50h], eax  [89 44 24 50]
    unknown_operand = reg_eax;

    // 0x3eb8: mov ebx, eax  [8b d8]
    reg_ebx = reg_eax;

    // 0x3eba: call 5d10h  [e8 51 1e 00 00]
    call_function_0x5d10();
    // >>> Function call detected

    // 0x3ebf: and dword ptr [rsp + 58h], 0  [83 64 24 58 00]
    unknown_operand &= 0;

    // 0x3ec4: mov edx, esi  [8b d6]
    reg_edx = reg_esi;

    // 0x3ec6: mov dword ptr [rsp + 54h], eax  [89 44 24 54]
    unknown_operand = reg_eax;

    // 0x3eca: mov rcx, rbp  [48 8b cd]
    reg_rcx = reg_rbp;

    // 0x3ecd: lea rax, [rsp + 50h]  [48 8d 44 24 50]
    reg_rax = &unknown_operand;

    // 0x3ed2: mov qword ptr [rsp + 30h], rax  [48 89 44 24 30]
    unknown_operand = reg_rax;

    // 0x3ed7: mov qword ptr [rsp + 28h], rdi  [48 89 7c 24 28]
    unknown_operand = reg_rdi;

    // 0x3edc: call 5cf8h  [e8 17 1e 00 00]
    call_function_0x5cf8();
    // >>> Function call detected

    // 0x3ee1: lea r11, [rsp + 60h]  [4c 8d 5c 24 60]
    reg_r11 = &unknown_operand;

    // 0x3ee6: mov eax, ebx  [8b c3]
    reg_eax = reg_ebx;

    // 0x3ee8: mov rbx, qword ptr [r11 + 10h]  [49 8b 5b 10]
    reg_rbx = unknown_operand;

    // 0x3eec: mov rbp, qword ptr [r11 + 18h]  [49 8b 6b 18]
    reg_rbp = unknown_operand;

    // 0x3ef0: mov rsi, qword ptr [r11 + 20h]  [49 8b 73 20]
    reg_rsi = unknown_operand;

    // 0x3ef4: mov rsp, r11  [49 8b e3]
    reg_rsp = reg_r11;

    // 0x3ef7: pop rdi  [5f]
    // POP reg_rdi

    // 0x3ef8: ret   [c3]
    return result;
    // >>> Function return


}

// ============================================
// Complete implementation of sub_18a2
// Original Address: 0x18a2
// Total Instructions: 27
// Basic Blocks: 3
// Register Usage: edx, rax, rbx, rcx, rsp
// ============================================
void sub_18a2(uint64_t param1) {
    // CPU Register simulation
    uint64_t reg_rdx = 0;  // Data register
    uint64_t reg_rsp = 0;  // Stack pointer
    uint64_t reg_rax = 0;  // Accumulator register
    uint64_t reg_rbx = 0;  // Base register
    uint64_t reg_rcx = 0;  // Counter register

    // CPU Flags simulation
    bool zero_flag = false;
    bool carry_flag = false;
    bool sign_flag = false;
    bool overflow_flag = false;

    // ============= Basic Block 1 =============
    // Address Range: 0x18a2 - 0x18d7
    // Instructions: 16

    // 0x18a2: sub rsp, 20h  [48 83 ec 20]
    reg_rsp -= 32;

    // 0x18a6: cmp dword ptr [rcx], 49534d4fh  [81 39 4f 4d 53 49]
    // Compare: unknown_operand vs 1230196047

    // 0x18ac: mov rbx, rcx  [48 8b d9]
    reg_rbx = reg_rcx;

    // 0x18af: mov rcx, qword ptr [rcx + 8]  [48 8b 49 08]
    reg_rcx = unknown_operand;

    // 0x18b3: je 18e3h  [74 2e]
    if (zero_flag) goto label_0x18e3;
    // >>> Control flow: Jump to 0x18e3

    // 0x18b5: test rcx, rcx  [48 85 c9]
    // Test: reg_rcx & reg_rcx

    // 0x18b8: je 18c6h  [74 0c]
    if (zero_flag) goto label_0x18c6;
    // >>> Control flow: Jump to 0x18c6

    // 0x18ba: call qword ptr [rip + 17757h]  [48 ff 15 57 77 01 00]
    // Function call
    // >>> Function call detected

    // 0x18c1: nop dword ptr [rax + rax]  [0f 1f 44 00 00]
    // ASM: nop dword ptr [rax + rax] (Address: 0x18c1)

    // 0x18c6: mov rcx, qword ptr [rbx + 10h]  [48 8b 4b 10]
    reg_rcx = unknown_operand;

    // 0x18ca: test rcx, rcx  [48 85 c9]
    // Test: reg_rcx & reg_rcx

    // 0x18cd: jne 18fah  [75 2b]
    if (!zero_flag) goto label_0x18fa;
    // >>> Control flow: Jump to 0x18fa

    // 0x18cf: mov rcx, rbx  [48 8b cb]
    reg_rcx = reg_rbx;

    // 0x18d2: add rsp, 20h  [48 83 c4 20]
    reg_rsp += 32;

    // 0x18d6: pop rbx  [5b]
    // POP reg_rbx

    // 0x18d7: jmp qword ptr [rip + 1773ah]  [48 ff 25 3a 77 01 00]
    goto label_unknown;
    // >>> Control flow: Jump detected


label_0x18e3:
    // ============= Basic Block 2 =============
    // Address Range: 0x18e3 - 0x18f8
    // Instructions: 7

    // 0x18e3: test rcx, rcx  [48 85 c9]
    // Test: reg_rcx & reg_rcx

    // 0x18e6: je 18cfh  [74 e7]
    if (zero_flag) goto label_0x18cf;
    // >>> Control flow: Jump to 0x18cf

    // 0x18e8: mov rax, qword ptr [rcx]  [48 8b 01]
    reg_rax = unknown_operand;

    // 0x18eb: mov edx, 1  [ba 01 00 00 00]
    reg_edx = 1;

    // 0x18f0: mov rax, qword ptr [rax]  [48 8b 00]
    reg_rax = unknown_operand;

    // 0x18f3: call 0e010h  [e8 18 c7 00 00]
    call_function_0xe010();
    // >>> Function call detected

    // 0x18f8: jmp 18cfh  [eb d5]
    goto label_0x18cf;
    // >>> Control flow: Jump to 0x18cf


label_0x18fa:
    // ============= Basic Block 3 =============
    // Address Range: 0x18fa - 0x1906
    // Instructions: 4

    // 0x18fa: mov rax, qword ptr [rcx]  [48 8b 01]
    reg_rax = unknown_operand;

    // 0x18fd: mov rax, qword ptr [rax + 10h]  [48 8b 40 10]
    reg_rax = unknown_operand;

    // 0x1901: call 0e010h  [e8 0a c7 00 00]
    call_function_0xe010();
    // >>> Function call detected

    // 0x1906: jmp 18cfh  [eb c7]
    goto label_0x18cf;
    // >>> Control flow: Jump to 0x18cf


}

// ============================================
// Complete implementation of sub_3d53
// Original Address: 0x3d53
// Total Instructions: 38
// Basic Blocks: 2
// Register Usage: eax, ecx, edi, r14, r15, r8, rax, rbx, rcx, rdi, rdx, rsi, rsp
// ============================================
uint64_t sub_3d53(void) {
    // CPU Register simulation
    uint64_t reg_rdx = 0;  // Data register
    uint64_t reg_rsp = 0;  // Stack pointer
    uint64_t reg_rax = 0;  // Accumulator register
    uint64_t reg_rsi = 0;  // Source index
    uint64_t reg_r14 = 0;  // General purpose register
    uint64_t reg_rdi = 0;  // Destination index
    uint64_t reg_rbx = 0;  // Base register
    uint64_t reg_rcx = 0;  // Counter register
    uint64_t reg_r8 = 0;  // General purpose register
    uint64_t reg_r15 = 0;  // General purpose register

    // CPU Flags simulation
    bool zero_flag = false;
    bool carry_flag = false;
    bool sign_flag = false;
    bool overflow_flag = false;

    // ============= Basic Block 1 =============
    // Address Range: 0x3d53 - 0x3dad
    // Instructions: 35

    // 0x3d53: mov qword ptr [rsp + 20h], rbx  [48 89 5c 24 20]
    unknown_operand = reg_rbx;

    // 0x3d58: test rbx, rbx  [48 85 db]
    // Test: reg_rbx & reg_rbx

    // 0x3d5b: je 3da0h  [74 43]
    if (zero_flag) goto label_0x3da0;
    // >>> Control flow: Jump to 0x3da0

    // 0x3d5d: mov qword ptr [rbx + 40h], r14  [4c 89 73 40]
    unknown_operand = reg_r14;

    // 0x3d61: lea rcx, [rbx + 10h]  [48 8d 4b 10]
    reg_rcx = &unknown_operand;

    // 0x3d65: call 43c0h  [e8 56 06 00 00]
    call_function_0x43c0();
    // >>> Function call detected

    // 0x3d6a: mov ecx, eax  [8b c8]
    reg_ecx = reg_eax;

    // 0x3d6c: test eax, eax  [85 c0]
    // Test: reg_eax & reg_eax

    // 0x3d6e: js 3d74h  [78 04]
    // ASM: js 3d74h (Address: 0x3d6e)
    // >>> Control flow: Jump to 0x3d74

    // 0x3d70: mov byte ptr [rbx + 38h], 1  [c6 43 38 01]
    unknown_operand = 1;

    // 0x3d74: xor eax, eax  [33 c0]
    reg_eax ^= reg_eax;

    // 0x3d76: test ecx, ecx  [85 c9]
    // Test: reg_ecx & reg_ecx

    // 0x3d78: cmovs eax, ecx  [0f 48 c1]
    // ASM: cmovs eax, ecx (Address: 0x3d78)

    // 0x3d7b: xor edi, edi  [33 ff]
    reg_edi ^= reg_edi;

    // 0x3d7d: test eax, eax  [85 c0]
    // Test: reg_eax & reg_eax

    // 0x3d7f: cmovs edi, eax  [0f 48 f8]
    // ASM: cmovs edi, eax (Address: 0x3d7f)

    // 0x3d82: test edi, edi  [85 ff]
    // Test: reg_edi & reg_edi

    // 0x3d84: jne 3dd2h  [75 4c]
    if (!zero_flag) goto label_0x3dd2;
    // >>> Control flow: Jump to 0x3dd2

    // 0x3d86: mov rax, qword ptr [rbx]  [48 8b 03]
    reg_rax = unknown_operand;

    // 0x3d89: mov r8, rsi  [4c 8b c6]
    reg_r8 = reg_rsi;

    // 0x3d8c: mov rdx, r15  [49 8b d7]
    reg_rdx = reg_r15;

    // 0x3d8f: mov rcx, rbx  [48 8b cb]
    reg_rcx = reg_rbx;

    // 0x3d92: mov rax, qword ptr [rax]  [48 8b 00]
    reg_rax = unknown_operand;

    // 0x3d95: call 0e010h  [e8 76 a2 00 00]
    call_function_0xe010();
    // >>> Function call detected

    // 0x3d9a: mov edi, eax  [8b f8]
    reg_edi = reg_eax;

    // 0x3d9c: test eax, eax  [85 c0]
    // Test: reg_eax & reg_eax

    // 0x3d9e: jne 3dd2h  [75 32]
    if (!zero_flag) goto label_0x3dd2;
    // >>> Control flow: Jump to 0x3dd2

    // 0x3da0: mov eax, edi  [8b c7]
    reg_eax = reg_edi;

    // 0x3da2: add rsp, 30h  [48 83 c4 30]
    reg_rsp += 48;

    // 0x3da6: pop r15  [41 5f]
    // POP reg_r15

    // 0x3da8: pop r14  [41 5e]
    // POP reg_r14

    // 0x3daa: pop rdi  [5f]
    // POP reg_rdi

    // 0x3dab: pop rsi  [5e]
    // POP reg_rsi

    // 0x3dac: pop rbx  [5b]
    // POP reg_rbx

    // 0x3dad: ret   [c3]
    return result;
    // >>> Function return


label_0x3dd2:
    // ============= Basic Block 2 =============
    // Address Range: 0x3dd2 - 0x3dda
    // Instructions: 3

    // 0x3dd2: mov rcx, rbx  [48 8b cb]
    reg_rcx = reg_rbx;

    // 0x3dd5: call 8b08h  [e8 2e 4d 00 00]
    call_function_0x8b08();
    // >>> Function call detected

    // 0x3dda: jmp 3da0h  [eb c4]
    goto label_0x3da0;
    // >>> Control flow: Jump to 0x3da0


}
