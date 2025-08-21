
#include <stdio.h>
#include <windows.h>

// Simple test functions for demonstration
int test_function_1(int param1, char* param2) {
    if (param1 > 0 && param2) {
        printf("Test function 1 called with: %d, %s\n", param1, param2);
        return param1 * 2;
    }
    return 0;
}

void test_function_2() {
    printf("Test function 2 called\n");
    
    // Simple loop for complexity
    for (int i = 0; i < 5; i++) {
        printf("Loop iteration: %d\n", i);
    }
}

BOOL WINAPI test_function_3(HWND hwnd, LPARAM lparam) {
    MessageBox(hwnd, L"Hello from test function 3!", L"Demo", MB_OK);
    return TRUE;
}

// Main function
int main() {
    printf("Demo binary for Binary Analyzer GUI\n");
    
    test_function_1(42, "Hello World");
    test_function_2();
    
    return 0;
}
