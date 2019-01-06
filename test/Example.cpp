/*
 *        __  __           _   _           ____
 *   ___ / _|/ _| ___  ___| |_(_)_   _____/ ___|  __ _ _ __
 *  / _ \ |_| |_ / _ \/ __| __| \ \ / / _ \___ \ / _` | '_ \
 * |  __/  _|  _|  __/ (__| |_| |\ V /  __/___) | (_| | | | |
 *  \___|_| |_|  \___|\___|\__|_| \_/ \___|____/ \__,_|_| |_|
 *
 * Example from the paper:
 *
 *     Gregory J. Duck and Roland H. C. Yap. 2018. EffectiveSan: Type and
 *     Memory Error Detection using Dynamically Typed C/C++.  In Proceedings
 *     of 39th ACM SIGPLAN Conference on Programming Language Design and
 *     Implementation (PLDI’18). ACM, New York, NY, USA, 15 pages.
 *     https://doi.org/10.1145/3192366.3192388
 */

#define NOINLINE    __attribute__((noinline))

struct T {int a[3]; char *s;};
struct S {float f; struct T t;};

/*
 * Get the i^th value of an array pointed to by `ptr'.
 *
 * NOTE: If this operation were inlined the compiler will likely optimize
 *       the operation away (since it is undefined behaviour).
 */
template <typename U>
static NOINLINE U getValue(U *ptr, int idx)
{
    return ptr[idx];
}

int main(void)
{
    S *s = new S[100];

    int *p = s[10].t.a;

    getValue<int>(p, 0);            // OK
    getValue<int>(p, 1);            // OK
    getValue<int>(p, 2);            // OK
    getValue<int>(p, 3);            // Bounds error
    getValue<int>(p, -1);           // Bounds error

    double *q = (double *)p;

    getValue<double>(q, 0);         // Type error

    delete[] s;

    getValue<int>(p, 0);            // UAF error

    return 0;
}

