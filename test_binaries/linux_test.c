#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

int test_function_3(int value) {
    if (value < 10) {
        return value + 1;
    } else if (value < 100) {
        return value * 2;
    } else {
        return value / 2;
    }
}

// Function with string operations
char* string_function(const char* input) {
    if (!input) return NULL;
    
    char* result = malloc(strlen(input) + 10);
    sprintf(result, "processed_%s", input);
    return result;
}

// Main function
int main() {
    printf("Demo binary for Binary Analyzer GUI\n");
    
    test_function_1(42, "Hello World");
    test_function_2();
    
    int result = test_function_3(50);
    printf("Function 3 result: %d\n", result);
    
    char* str_result = string_function("test");
    if (str_result) {
        printf("String function result: %s\n", str_result);
        free(str_result);
    }
    
    return 0;
}