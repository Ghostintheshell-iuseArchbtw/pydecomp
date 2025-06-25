#include <windows.h>
#include <stdio.h>

// Simple test DLL for the disassembler
BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved) {
    switch (dwReason) {
        case DLL_PROCESS_ATTACH:
            // Initialization code
            break;
        case DLL_PROCESS_DETACH:
            // Cleanup code
            break;
    }
    return TRUE;
}

// Simple arithmetic function
__declspec(dllexport) int AddNumbers(int a, int b) {
    return a + b;
}

// String function
__declspec(dllexport) char* FormatMessage(const char* name) {
    static char buffer[256];
    sprintf(buffer, "Hello, %s! Welcome to the test DLL.", name);
    return buffer;
}

// Function with loops and conditions
__declspec(dllexport) int ProcessArray(int* array, int size) {
    int sum = 0;
    for (int i = 0; i < size; i++) {
        if (array[i] > 0) {
            sum += array[i];
        }
    }
    return sum;
}

// Memory operation function
__declspec(dllexport) void* AllocateMemory(size_t size) {
    return malloc(size);
}

// Cleanup function
__declspec(dllexport) void FreeMemory(void* ptr) {
    if (ptr != NULL) {
        free(ptr);
    }
}
