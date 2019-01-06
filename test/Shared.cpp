/*
 *        __  __           _   _           ____
 *   ___ / _|/ _| ___  ___| |_(_)_   _____/ ___|  __ _ _ __
 *  / _ \ |_| |_ / _ \/ __| __| \ \ / / _ \___ \ / _` | '_ \
 * |  __/  _|  _|  __/ (__| |_| |\ V /  __/___) | (_| | | | |
 *  \___|_| |_|  \___|\___|\__|_| \_/ \___|____/ \__,_|_| |_|
 */

#include <cstdio>

#include "Test.h"

size_t passed = 0;
size_t failed = 0;
size_t total  = 0;

class GlobalWithConstructor
{
    int x;
    int y;

    public:
        GlobalWithConstructor(int i)
        {
            TEST_INIT(GlobalWithConstructor);
            x = i;
            y = 4;
        }
};

GlobalWithConstructor g(6);

