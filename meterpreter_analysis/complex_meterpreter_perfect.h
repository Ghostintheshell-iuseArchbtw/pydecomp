/*
 * Perfect C Header for complex_meterpreter.dll
 * Generated automatically from binary analysis
 * Architecture: x64
 * 
 * This header provides clean, well-documented function
 * declarations and type definitions for the recreated
 * binary functionality.
 */

#ifndef __COMPLEX_METERPRETER_H__
#define __COMPLEX_METERPRETER_H__

/* Standard includes */
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/* Windows API includes */
#ifdef _WIN32
#include <windows.h>
#include <winternl.h>
#endif

/* ================================================================
 * TYPE DEFINITIONS
 * ================================================================ */

/* CPU register simulation types */
typedef struct {
    uint64_t rax, rbx, rcx, rdx;
    uint64_t rsi, rdi, rbp, rsp;
    uint64_t r8, r9, r10, r11, r12, r13, r14, r15;
} cpu_registers_t;

typedef struct {
    bool zero_flag;
    bool carry_flag;
    bool sign_flag;
    bool overflow_flag;
    bool parity_flag;
    bool auxiliary_flag;
} cpu_flags_t;

/* ================================================================
 * FUNCTION DECLARATIONS
 * ================================================================ */

/* Internal functions - implementation details */
static uint64_t sub_1005(uint64_t param1);

static uint64_t sub_100a(void);

static uint64_t sub_1229(uint64_t param1);

static uint64_t sub_1260(uint64_t param1, uint64_t param2, uint64_t param3, uint64_t param4);

#endif /* __COMPLEX_METERPRETER_H__ */
