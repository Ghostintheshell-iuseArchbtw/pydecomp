/*
 * Perfect C Header for amsi.dll
 * Generated automatically from binary analysis
 * Architecture: x64
 * 
 * This header provides clean, well-documented function
 * declarations and type definitions for the recreated
 * binary functionality.
 */

#ifndef __AMSI_H__
#define __AMSI_H__

/* Standard includes */
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/* AMSI specific includes */
#ifdef _WIN32
#include <amsi.h>
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

/* Exported functions - main API */
#ifdef __cplusplus
extern "C" {
#endif

uint64_t AmsiCloseSession(uint64_t param1);
    /* Purpose: unknown */

HRESULT AmsiInitialize(LPCWSTR appName, HAMSICONTEXT* amsiContext);
    /* Purpose: wrapper_function */

uint64_t AmsiNotifyOperation(uint64_t param1, uint64_t param2, uint64_t param3, uint64_t param4);
    /* Purpose: wrapper_function */

uint64_t AmsiOpenSession(uint64_t param1, uint64_t param2);
    /* Purpose: unknown */

HRESULT AmsiScanBuffer(HAMSICONTEXT amsiContext, PVOID buffer, ULONG length, LPCWSTR contentName, HAMSISESSION amsiSession, AMSI_RESULT* result);
    /* Purpose: wrapper_function */

bool AmsiScanString(uint64_t param1, uint64_t param2, uint64_t param3);
    /* Purpose: wrapper_function */

void* AmsiUacInitialize(uint64_t param1);
    /* Purpose: wrapper_function */

HRESULT AmsiUacScan(uint64_t param1, uint64_t param2, uint64_t param3, uint64_t param4);
    /* Purpose: wrapper_function */

void* AmsiUacUninitialize(uint64_t param1);
    /* Purpose: wrapper_function */

void* AmsiUninitialize(uint64_t param1);
    /* Purpose: wrapper_function */

uint64_t DllCanUnloadNow(uint64_t param1);
    /* Purpose: wrapper_function */

uint64_t DllGetClassObject(uint64_t param1, uint64_t param2, uint64_t param3);
    /* Purpose: wrapper_function */

bool DllRegisterServer(void);
    /* Purpose: unknown */

bool DllUnregisterServer(void);
    /* Purpose: unknown */

#ifdef __cplusplus
}
#endif

/* Internal functions - implementation details */
static uint64_t sub_1120(uint64_t param1);

static uint64_t sub_1140(uint64_t param1);

static uint64_t sub_1274(uint64_t param1, uint64_t param2, uint64_t param3);

static uint64_t sub_12a6(uint64_t param1, uint64_t param2, uint64_t param3);

static uint64_t sub_1408(uint64_t param1, uint64_t param2, uint64_t param3);

static uint64_t sub_1411(uint64_t param1, uint64_t param2, uint64_t param3);

static uint64_t sub_1585(uint64_t param1);

static uint64_t sub_1748(uint64_t param1);

static uint64_t sub_1753(uint64_t param1, uint64_t param2, uint64_t param3, uint64_t param4);

static uint64_t sub_1842(uint64_t param1);

#endif /* __AMSI_H__ */
