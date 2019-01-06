#ifndef __TEST_H
#define __TEST_H

extern size_t passed;
extern size_t failed;
extern size_t total;

extern "C"
{
extern bool lowfat_is_ptr(const void *ptr);
}

#define STR0(x)         #x
#define STR(x)          STR0(x)

#define TEST_INIT(OBJ)                                                      \
    do {                                                                    \
        total++;                                                            \
        void *sp;                                                           \
        asm volatile ("movq %%rsp, %0" : "=r"(sp));                         \
        printf("[%.3zu] ", total);                                          \
        if (!lowfat_is_ptr(sp)) {                                           \
            failed++;                                                       \
            printf("\33[31mFAILED\33[0m: " STR(OBJ)                         \
                " \33[33m[stack is not low-fat]\33[0m\n");                  \
            return;     /* Return to avoid a crash */                       \
        } else {                                                            \
            passed++;                                                       \
            printf("\33[32mpassed\33[0m: " STR(OBJ)                         \
                " \33[33m[stack is low-fat]\33[0m\n");                      \
        }                                                                   \
    } while (false)

#endif
