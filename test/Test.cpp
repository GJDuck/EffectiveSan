/*
 *        __  __           _   _           ____
 *   ___ / _|/ _| ___  ___| |_(_)_   _____/ ___|  __ _ _ __
 *  / _ \ |_| |_ / _ \/ __| __| \ \ / / _ \___ \ / _` | '_ \
 * |  __/  _|  _|  __/ (__| |_| |\ V /  __/___) | (_| | | | |
 *  \___|_| |_|  \___|\___|\__|_| \_/ \___|____/ \__,_|_| |_|
 *
 *
 * The EffectiveSan test suite.
 */

#include <cassert>
#include <ccomplex>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include <vector>
#include <map>
#include <set>

#include "Test.h"

#define NOINLINE            __attribute__((__noinline__))

#define OFFSET(ptr, T, i)   ((T *)((uintptr_t)(ptr)+(i)*sizeof(T)))

extern "C"
{
extern size_t effective_get_num_type_errors(void);
extern size_t effective_get_num_bounds_errors(void);
}

#define TEST(OP, expected_type_errors, expected_bounds_errors)              \
    do {                                                                    \
        total++;                                                            \
        size_t saved_num_type_errors = effective_get_num_type_errors();     \
        size_t saved_num_bounds_errors = effective_get_num_bounds_errors(); \
        OP;                                                                 \
        size_t final_num_type_errors = effective_get_num_type_errors();     \
        size_t final_num_bounds_errors = effective_get_num_bounds_errors(); \
        size_t total_type_errors = final_num_type_errors -                  \
            saved_num_type_errors;                                          \
        size_t total_bounds_errors = final_num_bounds_errors -              \
            saved_num_bounds_errors;                                        \
        printf("[%.3zu] ", total);                                          \
        if (total_type_errors != (expected_type_errors) ||                  \
            total_bounds_errors != (expected_bounds_errors)) {              \
            failed++;                                                       \
            printf("\33[31mFAILED\33[0m: " STR(OP)                          \
                " \33[33m[excepted %zu type error(s) (got %zu); "           \
                "expected %zu bounds error(s) (got %zu)]\33[0m\n",          \
                (size_t)(expected_type_errors), total_type_errors,          \
                (size_t)(expected_bounds_errors), total_bounds_errors);     \
        } else {                                                            \
            passed++;                                                       \
            printf("\33[32mpassed\33[0m: " STR(OP)                          \
                " \33[33m[got %zu type error(s), "                          \
                "%zu bounds error(s)]\33[0m\n",                             \
                total_type_errors, total_bounds_errors);                    \
        }                                                                   \
    } while (false)

typedef long long longs __attribute__((__vector_size__(16)));

const longs LS __attribute__((__aligned__(16))) = {123456789, 0xDEADBEEFull};
longs       MS = {1, 2};

class GlobalWithConstructor2
{
    int x;
    int y;

    public:
        GlobalWithConstructor2(int i)
        {
            TEST_INIT(GlobalWithConstructor2);
            x = i;
            y = 4;
        }
};

GlobalWithConstructor2 g(6);

class RealBase
{
    public:
        
        double value;

        RealBase() : value(123.456) { }

        NOINLINE double getValue()
        {
            return value;
        }
};

class Base : public RealBase
{
    protected:

        Base(int a, float b) : x(a), y(b) { }

        int x;
        float y;

    public:

        Base () : x(0), y(1) { }

        virtual int f()
        {
            return x;
        }

        NOINLINE int sum()
        {
            return x + (int)y;
        }
};

class Derived : public Base
{
    public:

    char s[10];

    Derived() : Base(3, 4.0)
    {
        memset(s, 0, sizeof(s));   
    }
};

class Derived2 : public Base
{
    public:

        Base another;

        int xs[3];

        NOINLINE int sum()
        {
            return xs[0] + xs[1] + xs[2];
        }
};

class SSS
{
    public:
        int is[3];
        float fs[3];
        SSS()
        {
            memset(is, 1, sizeof(is));
            memset(fs, 0, sizeof(fs));
        };
};

class AAA : public Derived
{
    public:
        int x;
        float y;
        SSS s1;
        int *p;
        AAA() : x(0), y(3.0), p(nullptr) { }
};

class BBB : public AAA
{
    public:
        char n[10];
        int a;
        int b;
        int c;
        double g;
        BBB() : n("str"), a(1), b(2), c(3), g(1.0) { }
        virtual NOINLINE int method(int x)
        {
            return x + a - b + c;
        }
        NOINLINE int method2(int x)
        {
            return x + a - b + c;
        }
};

class BBB2 : public AAA
{
    public:
        bool t;
        bool u;
        bool v;
        NOINLINE bool logic()
        {
            return (!t && u) || v;
        }
};

class CCC
{
    public:
        AAA *p1;
        BBB *p2;
        SSS s2;
        CCC() : p1(nullptr), p2(nullptr) { }
        virtual NOINLINE void set(int x)
        {
            s2.is[1] = x;
        }
};

class DDD : public CCC, public BBB
{
    public:
        bool b;
        char ccc;
        char s[4];
        int xxx;
        DDD() : b(true), ccc('x'), s("g") { }
        NOINLINE void set(int x)
        {
            xxx = x;
        }
};

NOINLINE int call_f(Base &b)
{
    return b.f();
}

enum ENUM
{
    AAAA,
    BBBB = 444,
    CCCC
};

class Virtual
{
    public:
        void *p0;
        int *p1;
        float *p2;
        Virtual() : p0(nullptr), p1(nullptr), p2(nullptr) { }
        NOINLINE bool method()
        {
            return p0 == (void *)this;
        }
};

class XXX: virtual public Virtual
{
    public:
        double *p3;
        short *p4;
        XXX() : p3(nullptr), p4(nullptr) { }
};

class YYY: public XXX
{
    public:
        char *p5;
        CCC *p6;
        YYY() : p5(nullptr), p6(nullptr) { }
};

template <typename T>
class NTD   // Non-Trivial Destructor
{
    int len;
    T *p;

public:

    NOINLINE int getLen()
    {
        return len;
    }

    NOINLINE T get(int n)
    {
        return p[n];
    }

    NOINLINE void set(int n, T x)
    {
        p[n] = x;
    }

    NOINLINE NTD() : len(10)
    {
        p = new T[len];
    }

    NOINLINE ~NTD()
    {
        delete[] p;
    }
};

struct test_bug
{
    int a[2];
    char c;
} *p;

struct TUPLE
{
    int x;
    int y;
};

struct BITFIELDS
{
    int x:1;
    int y:1;
    unsigned q:3;
    int z:20;
    unsigned h:21;
    unsigned long long u:33;
    unsigned long long v:10;
};

struct Nest_8
{
    int i;
    float data[10];
};
struct Nest_7 { int i; struct Nest_8 n; };
struct Nest_6 { int i; struct Nest_7 n; };
struct Nest_5 { int i; struct Nest_6 n; };
struct Nest_4 { int i; struct Nest_5 n; };
struct Nest_3 { int i; struct Nest_4 n; };
struct Nest_2 { int i; struct Nest_3 n; };
struct Nest_1 { int i; struct Nest_2 n; };
struct Nest_0 { int i; struct Nest_1 n; };
typedef struct Nest_0 Nest;

struct AnonSubObj
{
    int x;
    float y;
    struct
    {
        int q;
        int r;
    } a;
    char c;
    TUPLE t;
    union
    {
        float f;
        int i;
    } U;
    char buf[10];
    struct
    {
        short z;
        int w;
    } s;
    char buf2[2];
    union
    {
        long long l;
        void *p;
    } V;
};

NOINLINE int getAnon(void *p0)
{
    struct
    {
        int x;
        int y;
    } *p;
    memcpy(&p, &p0, sizeof(p));
    return p->y;
}

NOINLINE float getAnon2(void *p0)
{
    union
    {
        int a;
        float b;
    } *p;
    memcpy(&p, &p0, sizeof(p));
    return p->b;
}

NOINLINE float testNarrowNest(Nest *ns, int i, int j)
{
    ns += i;
    float *data = ns->n.n.n.n.n.n.n.n.data;
    return data[j];
}

template <typename T>
struct ListNode
{
    T val;
    ListNode<T> *next;
};

template <typename T>
struct TreeNode
{
    T val;
    TreeNode<T> *left;
    TreeNode<T> *right;
};

struct Big
{
    double d;
    float f;
    int i;
    short s;
    char c;
};
typedef struct Big BIG;

int Big::* ptr2memb = &Big::i;      // C++ pointer-to-member.

#define make_big(i)                 \
    ((Big){(double)i, (float)i, (int)i, 99, 55})

static bool operator<(const Big &b1, const Big &b2)
{
    return (b1.d < b2.d);
}

template <typename T>
struct Vector
{
    int len;
    T data[];   // FAM
};

union Union
{
    int i[10];
    float f[3];
    struct Big b;
    void *p[4];
};

template <typename T>
NOINLINE T testNarrowVector(Vector<T> *V, int i)
{
    T *data = V->data;
    return data[i];
}

struct SubObjs
{
    char pad[10];
    ListNode<double> x;
    TreeNode<long long> y;
    Nest n;
    char pad2[10];
};

typedef short shorts __attribute__((__vector_size__(16)));
typedef int ints __attribute__((__vector_size__(16)));
typedef float floats __attribute__((__vector_size__(16)));
typedef double doubles __attribute__((__vector_size__(16)));

int (*global_func)(int *x, int i) = nullptr;
int global_func_def(int *ptr, int i)
{
    return ptr[i];
}
float global_func_def2(float *ptr, int i)
{
    return ptr[i];
}

typedef void *voidptr_t;
typedef char *charptr_t;
typedef signed char *signedcharptr_t;
typedef short *shortptr_t;
typedef TUPLE *tupleptr_t;

struct T {int a[3]; char *s;};
struct S {float f; struct T t;};

template <typename T>
NOINLINE void nop(T x)
{
    return; // NOP
}

template <typename T>
NOINLINE ListNode<T> *makeList(int n, T x)
{
    ListNode<T> *xs = nullptr;
    for (int i = 0; i < n; i++)
    {
        ListNode<T> *node = new ListNode<T>;
        node->val = x;
        node->next = xs;
        xs = node;
    }
    return xs;
}

template <typename T>
NOINLINE TreeNode<T> *makeTree(int n, T x)
{
    if (n <= 0)
        return nullptr;
    TreeNode<T> *left = makeTree(n-1, x);
    TreeNode<T> *right = makeTree(n-1, x);
    TreeNode<T> *node = new TreeNode<T>;
    node->val = x;
    node->left = left;
    node->right = right;
    return node;
}

template <typename T>
NOINLINE void freeList(ListNode<T> *xs)
{
    while (xs != nullptr)
    {
        ListNode<T> *node = xs;
        xs = xs->next;
        delete node;
    }
}

template <typename T>
NOINLINE T sumList(ListNode<T> *xs)
{
    T sum = 0;
    while (xs != nullptr)
    {
        sum += xs->val;
        xs = xs->next;
    }
    return sum;
}

template <typename T>
NOINLINE T sumVector(Vector<T> &X)
{
    T sum = 0;
    for (int i = 0; i < X.len; i++)
        sum += X.data[i];
    return sum;
}

NOINLINE int sumTuple(TUPLE *t)
{
    return t->x + t->y;
}

template <typename T>
NOINLINE T sumArray(T *a, int len)
{
    T sum = 0;
    for (int i = 0; i < len; i++)
        sum += a[i];
    return sum;
}

template <typename T>
NOINLINE T get(T *p, int i)
{
    return p[i];
}

template <typename T>
NOINLINE T get(ListNode<T> *xs)
{
    return xs->val;
}

template <typename T>
NOINLINE void set(T *p, T val)
{
    *p = val;
}

template <typename T>
NOINLINE void copy(T *dst, const T *src)
{
    *dst = *src;
}

struct MultiDim
{
    int i[2][3][4];
    float f[5][6][7];
};

static NOINLINE const int *getPtr()
{
    static int xs[3] = {1, 2, 3};
    return xs;
}

static NOINLINE int indirectCall(const int *(*f)(), int idx)
{
    const int *ptr = f();
    return ptr[idx];
}

template <typename T>
static NOINLINE int passByCopy(T obj)
{
    char *ptr = (char *)&obj;
    return *(int *)ptr;
}

static char globalArray[10];

template <typename T>
static NOINLINE T id(T x)
{
    return x;
}

class A
{
    private:

        int x;

    public:

        A(int y) : x(y) { }

        virtual void f(void)
        {
            // printf("HIJACKED!\n");
        }
};


class B
{
    private:

        float z;

    public:

        void *buf[3];

        B(float w) : z(w) { }

        virtual void g(void)
        {
            // printf("OK\n");
        }
};

class C
{
    private:

        void *ptr;

    public:

        float pad1;             // Pad to same size as B
        void *pad2[3];

        C() : ptr(nullptr) { }

        void set(void *x)
        {
            ptr = x;
        }
};

static NOINLINE void overflow(void **buf, long long idx, void *ptr)
{
    buf[idx] = ptr;
}

static NOINLINE void confusion(C *c, void *ptr)
{
    c->set(ptr);
}

struct stuff
{
    wchar_t str[42];
    bool blah;
    float x;
};

/* Use wchar_t to avoid the special treatment of char*. */
__attribute__((__always_inline__))
wchar_t *my_wmemset(wchar_t *wcs, wchar_t wc, size_t n)
{
    while (n-- > 0) *wcs++ = wc;
    return wcs;
}

int main(int argc, char **argv)
{
    if (argc == 2 && strcmp(argv[1], "--show-errors") == 0)
        /*NOP*/;
    else if (argc != 1)
    {
        setenv("EFFECTIVE_LOGFILE", "/dev/null", true);
        fprintf(stderr, "usage: %s [--show-errors]\n", argv[0]);
        return EXIT_FAILURE;
    }
    else
        setenv("EFFECTIVE_LOGFILE", "/dev/null", true);

{
    int i = 0;
    float f = 0.0f;
    TEST(*(int *)&f = 1, 1, 0);
    TEST(*(float *)&i = 1.0f, 1, 0);
}

{
    TUPLE tup = {3, 5};
    int ints[2] = {5, 4};
    TEST(sumTuple(&tup), 0, 0);
    TEST(sumTuple((TUPLE *)ints), 1, 0);
}

{
    // Basic arrays:
    int i = 0;
    int j[] = {1, 2, 3, 4};
    TUPLE T = {0, 1};
    TEST(get(&i, 0), 0, 0);
    TEST(get(&i, 1), 0, 1);
    TEST(get(&i, -1), 0, 1);
    TEST(get(j, 0), 0, 0);
    TEST(get(j, 3), 0, 0);
    TEST(get(j, -1), 0, 1);
    TEST(get(j, 4), 0, 1);
    TEST(get(&T, 0), 0, 0);
    TEST(get(&T, 1), 0, 1);
    TEST(get(&T, -1), 0, 1);
}

    ListNode<int> *xs   = makeList(10, 3);
    ListNode<float> *ys = makeList(10, 3.0f);
    TreeNode<unsigned long long> *t = makeTree(3, (unsigned long long)10);

    TEST(sumList(xs), 0, 0);
    TEST(sumList((ListNode<int> *)ys), 10, 0);   // int vs float per node
    TEST(get<int>((int *)xs, 0), 0, 0);
    TEST(get<int>((int *)ys, 0), 1, 0);
    TEST(get<int>((int *)xs, 1), 0, 1);
    TEST(get<int>((int *)xs, -1), 0, 1);
    TEST(get<int>((int *)xs+1, 0), 1, 0);
    TEST(get<int>((int *)&xs, 0), 1, 0);
    TEST(get<float>((float *)xs, 0), 1, 0);
    TEST(sumList((ListNode<int> *)t), 3, 0);     // Follows left branch
    char *ptr = (char *)xs;
    for (int i = 0; i < 4; i++)
    {
        // 2 type errors: 1xescape + 1xget
        TEST(get((ListNode<int> *)(ptr+i)), (i == 0? 0: 1), 0);
    }

{
    // Untyped
    char untyped[100];      // Untyped memory cannot cause type errors
    TEST(get<int>((int *)untyped, 0), 0, 0);
    TEST(get<float>((float *)untyped, 0), 0, 0);
    memcpy(untyped, xs, sizeof(*xs));
    TEST(sumList((ListNode<int> *)untyped), 0, 0);
    TEST(get<int>((int *)untyped+1, 0), 0, 0);
    TEST(get<int>((int *)untyped, 100), 0, 1);
    TEST(get<int>((int *)untyped, -1), 0, 1);
}

{
    // Vectors
    TEST(get<long long>((long long *)&LS, 0), 0, 0);
    TEST(get<long long>((long long *)&LS, 1), 0, 0);
    TEST(get<long long>((long long *)&LS, -1), 0, 1);
    TEST(get<long long>((long long *)&LS, 2), 0, 1);
    TEST(get<long long>((long long *)&MS, 0), 0, 0);
    TEST(get<long long>((long long *)&MS, 1), 0, 0);
    TEST(get<long long>((long long *)&MS, -1), 0, 1);
    TEST(get<long long>((long long *)&MS, 2), 0, 1);
    TEST(get<double>((double *)&LS, 0), 1, 0);
    TEST(get<double>((double *)&MS, 0), 1, 0);
}

{
    Derived d;
    TEST(d.sum(), 0, 0);
    TEST(call_f(d), 0, 0);
    TEST(get<int>((int *)d.s, 0), 0, 0);
    TEST(get<float>((float *)(d.s + 5), 0), 0, 0);

    Nest n;
    for (int i = 0; i < 9; i++)
        TEST(get<int>(OFFSET(&n, int, i), 0), 0, 0);
    for (int i = 0; i < 3; i++)
        TEST(get<float>(OFFSET(&n, float, i), 0), 1, 0);
    TEST(get<float>((float *)OFFSET(&n, int, 9), 2), 0, 0);
    float *fs = n.n.n.n.n.n.n.n.n.data;
    TEST(get<float>(fs, -1), 0, 1);
    TEST(get<float>(fs, 0), 0, 0);
    TEST(get<float>(fs, 9), 0, 0);
    TEST(get<float>(fs, 10), 0, 1);
}

{
    // Test bitfields:
    struct BITFIELDS *b = (struct BITFIELDS *)malloc(sizeof(struct BITFIELDS));
    TEST(sumTuple((TUPLE *)b), 1, 0);
    TEST(get<int>((int *)b, 0), 0, 0);
    TEST(get<int>((int *)b, 1), 0, 1);
    TEST(get<int>((int *)b, -1), 0, 1);
    TEST(get<unsigned>((unsigned *)b, 0), 0, 0);
    TEST(get<float>((float *)b, 0), 1, 0);
    TEST(get<int>((int *)b+1, 0), 0, 0);
    TEST(get<int>((int *)b+1, 1), 0, 1);
    TEST(get<int>((int *)b+1, -1), 0, 1);
    TEST(get<int>((int *)((char *)b+8), 0), 1, 0);
    TEST(get<unsigned long long>((unsigned long long *)((char *)b+8), 0), 0, 0);
    TEST(get<unsigned long long>((unsigned long long *)((char *)b+8), 1), 0, 1);
    TEST(get<unsigned long long>((unsigned long long *)((char *)b+8), -1), 0, 1);
}

{
    // Test sub-objects:
    SubObjs *ss = (SubObjs *)malloc(sizeof(SubObjs));
    memset(ss, 0, sizeof(SubObjs));
    TEST(sumList((&ss->x)), 0, 0);
    TEST(get<double>((double *)(&ss->x), 0), 0, 0);
    TEST(get<double>((double *)(&ss->x), 1), 0, 1);
    TEST(get<double>((double *)(&ss->x), -1), 0, 1);
    TEST(get<double>((double *)(&ss->x)+1, 0), 1, 0);
    char *ptr = (char *)(&ss->x);
    for (int i = 0; i < 4; i++)
    {
        // 2 type errors: 1xescape + 1xget
        TEST(get((ListNode<double> *)(ptr+i)), (i == 0? 0: 1), 0);
    }

    float *fs = ss->n.n.n.n.n.n.n.n.n.data;
    TEST(get<float>(fs, -1), 0, 1);
    TEST(get<float>(fs, 0), 0, 0);
    TEST(get<float>(fs, 9), 0, 0);
    TEST(get<float>(fs, 10), 0, 1);
    TEST(sumArray(fs, 10), 0, 0);

    Derived2 d2;
    TEST(d2.another.sum(), 0, 0);
    TEST(d2.another.getValue(), 0, 0);
    TEST(get<RealBase>(static_cast<RealBase *>(&d2.another), 0), 0, 0);
    TEST(get<Base>(static_cast<Base *>(&d2.another), 0), 0, 0);
    TEST(get<TUPLE>((TUPLE *)(&d2.another), 0), 1, 0);
}

{
    // Test VLAs;
    Vector<short> *V =
        (Vector<short> *)malloc(sizeof(Vector<short>) + 8 * sizeof(short));
    V->len = 8;
    for (int i = 0; i < V->len; i++)
        V->data[i] = i;
    Vector<TUPLE> *X =
        (Vector<TUPLE> *)malloc(sizeof(Vector<TUPLE>) + 10 * sizeof(TUPLE));
    X->len = 10;
    memset(X->data, 0, 10 * sizeof(TUPLE));
    TEST(sumVector(*V), 0, 0);
    TEST(sumVector(*(Vector<short> *)X), 1, 0);
    TEST(get(V->data, -1), 0, 1);
    TEST(get(V->data, 0), 0, 0);
    TEST(get(V->data, 7), 0, 0);
    TEST(get(V->data, 8), 0, 1);
    TEST(sumArray(V->data, 8), 0, 0);
    for (int i = 0; i < 5; i++)
        TEST(get(OFFSET(X, int, i), 0), 0, 0);
    for (int i = 0; i < 3; i++)
        TEST(sumTuple(X->data+i), 0, 0);
    for (int i = 0; i < 3; i++)
        TEST(sumTuple(((TUPLE *)(((int *)X->data)+1))+i), 1, 0);
    TUPLE *src = &X->data[1];
    TUPLE *dst = &X->data[2];
    TEST(*dst = *src, 0, 0);
    Vector<BIG> *Y = (Vector<BIG> *)
        malloc(sizeof(Vector<BIG>) + 6 * sizeof(BIG));
    Y->len = 6;
    memset(Y->data, 0, 6 * sizeof(BIG));
    for (int i = 0; i < 5; i++)
    {
        BIG *src = &Y->data[i];
        BIG *dst = src+1;
        TEST(copy(dst, src), 0, 0);
    }
}

{
    // Narrowing:
    TUPLE T = {100, -100};
    TEST(get((int *)&T, 0), 0, 0);
    TEST(get((int *)&T, 1), 0, 1);
    TEST(get((int *)&T, 2), 0, 1);
    TEST(get((int *)&T, -1), 0, 1);
    Nest ns[5];
    memset(ns, 0, sizeof(ns));
    TEST(testNarrowNest(ns, 0, 0), 0, 0);
    TEST(testNarrowNest(ns, 0, 9), 0, 0);
    TEST(testNarrowNest(ns, 0, -1), 0, 1);
    TEST(testNarrowNest(ns, 0, 10), 0, 1);
    TEST(testNarrowNest(ns, 4, 0), 0, 0);
    TEST(testNarrowNest(ns, 4, 9), 0, 0);
    TEST(testNarrowNest(ns, 4, -1), 0, 1);
    TEST(testNarrowNest(ns, 4, 10), 0, 1);
    TEST(testNarrowNest(ns, -1, 0), 0, 1);
    TEST(testNarrowNest(ns, -1, 9), 0, 1);
    TEST(testNarrowNest(ns, -1, -1), 0, 1);
    TEST(testNarrowNest(ns, -1, 10), 0, 1);
    TEST(testNarrowNest(ns, 5, 0), 0, 1);
    TEST(testNarrowNest(ns, 5, 9), 0, 1);
    TEST(testNarrowNest(ns, 5, -1), 0, 1);
    TEST(testNarrowNest(ns, 5, 10), 0, 1);
    Vector<char> *V = (Vector<char> *)malloc(sizeof(struct Vector<char>) + 23);
    V->len = 23;
    TEST(testNarrowVector(V, 0), 0, 0);
    TEST(testNarrowVector(V, 22), 0, 0);
    TEST(testNarrowVector(V, -1), 0, 1);
    TEST(testNarrowVector(V, 23), 0, 1);
    Vector<int> *U = (Vector<int> *)V->data;    // Vector inside a vector
    TEST(testNarrowVector(U, 0), 0, 0);
    TEST(testNarrowVector(U, 3), 0, 0);
    TEST(testNarrowVector(U, -1), 0, 1);
    TEST(testNarrowVector(U, 4), 0, 1);
}

{
    // Inheritance
    DDD *d = new DDD;
    TEST(sumArray(d->s1.is, 3), 0, 0);
    TEST(sumArray(d->s1.fs, 3), 0, 0);
    TEST(sumArray(d->s1.is, 4), 0, 1);
    TEST(sumArray(d->s1.fs, 4), 0, 1);
    TEST(sumArray(d->s2.is, 3), 0, 0);
    TEST(sumArray(d->s2.fs, 3), 0, 0);
    TEST(sumArray(d->s2.is, 4), 0, 1);
    TEST(sumArray(d->s2.fs, 4), 0, 1);
    TEST(d->set(333), 0, 0);
    TEST(d->method(4), 0, 0);
    TEST(static_cast<CCC *>(d)->set(444), 0, 0);
    TEST(static_cast<BBB *>(d)->method(2), 0, 0);
    TEST(dynamic_cast<CCC *>(d)->set(444), 0, 0);
    TEST(dynamic_cast<BBB *>(d)->method(2), 0, 0);
    Base *base = static_cast<Base *>(d);    // (Base *)((uintptr_t)d);
    TEST(static_cast<DDD *>(base)->set(222), 0, 0);
    TEST(static_cast<BBB *>(base)->method(3), 0, 0);
    TEST(dynamic_cast<DDD *>(base)->set(222), 0, 0);
    TEST(dynamic_cast<BBB *>(base)->method(3), 0, 0);
    TEST(static_cast<Derived2 *>(base)->sum(), 1, 0);   // bad downcast
    TEST(static_cast<BBB2 *>(base)->logic(), 1, 0);     // bad downcast
}

{
    // Virtual inheritance
    YYY *y = new YYY;
    TEST(y->method(), 0, 0);
    TEST(static_cast<XXX *>(y)->method(), 0, 0);
    TEST(static_cast<Virtual *>(y)->method(), 0, 0);
    TEST(dynamic_cast<XXX *>(y)->method(), 0, 0);
    TEST(dynamic_cast<Virtual *>(y)->method(), 0, 0);
    XXX *x = static_cast<XXX *>(y);
    Virtual *v = (Virtual *)((uintptr_t)x + 3*sizeof(void *));
    TEST(v->method(), 1, 0);
    x = new XXX;
    TEST(x->method(), 0, 0);
    TEST(static_cast<Virtual *>(x)->method(), 0, 0);
    TEST(dynamic_cast<Virtual *>(x)->method(), 0, 0);
    v = (Virtual *)((uintptr_t)x + 3*sizeof(void *));
    TEST(v->method(), 0, 0);
}

{
    // Unions
    Union *u = (Union *)malloc(sizeof(union Union));
    memset(u, 0, sizeof(union Union));
    TEST(get(u->i, -1), 0, 1);
    TEST(get(u->i, 0), 0, 0);
    TEST(get(u->i, 9), 0, 0);
    TEST(get(u->i, 10), 0, 1);
    TEST(get(u->f, -1), 0, 1);
    TEST(get(u->f, 0), 0, 0);
    TEST(get(u->f, 2), 0, 0);
    TEST(get(u->f, 3), 0, 1);
    TEST(get((double *)u, -1), 0, 1);   // u->b.d
    TEST(get((double *)u, 0), 0, 0);
    TEST(get((double *)u, 1), 0, 1);
    TEST(get((short *)u, -1), 1, 0);    // no match = type error
    TEST(get((short *)u, 0), 1, 0);
    TEST(get((short *)u, 1), 1, 0);
    TEST(get(&u->b.f, -3), 0, 1);
    TEST(get(&u->b.f, -2), 0, 0);       // widened to u.f  = no bounds error
    TEST(get(&u->b.f, 0), 0, 0);
    TEST(get(&u->b.f, 1), 0, 1);
    Vector<Union> *X =
        (Vector<Union> *)malloc(sizeof(Vector<Union>) + 10 * sizeof(Union));
    TEST(set(&X->data[3].p[1], (void *)u), 0, 0);
    TEST(set((Union **)&X->data[2].p[0], u), 0, 0);
    TEST(set((short *)&X->data[4].p[0], (short)777), 1, 0);
    TEST(copy(X->data, u), 0, 0);
    TEST(copy(&X->len, &u->b.i), 0, 0);
    TEST(copy(&X->len, (int *)&u->b.f), 0, 0);  // overlap = no type error
}

{
    // New arrays
    NTD<int> *xs = new NTD<int>[5];
    TEST(xs[-1].getLen(), 0, 1);
    TEST(xs[0].getLen(), 0, 0);
    TEST(xs[0].get(-1), 0, 1);
    TEST(xs[0].get(0), 0, 0);
    TEST(xs[5].getLen(), 0, 1);
    TEST(get((size_t *)xs-1, 0), 0, 0);         // read cookie
    TEST(get((int *)xs, 0), 0, 0);
    TEST(get((int *)xs, 1), 0, 1);
    TEST(get((float *)xs, 0), 1, 0);
    TEST(get((int **)xs + 1, 0), 0, 0);
    TEST(get((void **)xs + 1, 0), 0, 0);
    TEST(get((short **)xs + 1, 0), 1, 0);
    TEST(get((int **)xs + 1, 1), 0, 1);
    TEST(get(get((int **)xs + 1, 0), 0), 0, 0);
    TEST(get(get((int **)xs + 1, 0), -1), 0, 1);
    TEST(get(get((int **)xs + 1, 0), 10), 0, 1);
    TEST(get((int *)(&xs[4]), 0), 0, 0);
    TEST(get((int *)(&xs[4]), 1), 0, 1);
    TEST(get((float *)(&xs[4]), 0), 1, 0);
    TEST(get((int **)(&xs[4]) + 1, 0), 0, 0);
    TEST(get((void **)(&xs[4]) + 1, 0), 0, 0);
    TEST(get((short **)(&xs[4]) + 1, 0), 1, 0);
    TEST(get((int **)(&xs[4]) + 1, 1), 0, 1);
    TEST(get(get((int **)(&xs[4]) + 1, 0), 0), 0, 0);
    TEST(get(get((int **)(&xs[4]) + 1, 0), -1), 0, 1);
    TEST(get(get((int **)(&xs[4]) + 1, 0), 10), 0, 1);
    delete[] xs;
    NTD<NTD<float>> *ys = new NTD<NTD<float>>[5];
    TEST(ys[-1].getLen(), 0, 1);
    TEST(ys[0].getLen(), 0, 0);
    TEST(ys[0].get(0), 0, 0);
    TEST(ys[5].getLen(), 0, 1);
    TEST(get((size_t *)ys-1, 0), 0, 0);         // read cookie
    delete[] ys;
}

{
    // Multi-dimensional arrays.
    MultiDim m;
    memset(&m, 0, sizeof(m));
    TEST(get((int *)m.i, -1), 0, 1);
    TEST(get((int *)m.i, 0), 0, 0);
    TEST(get((int *)m.i, 3), 0, 0);
    TEST(get((int *)m.i, 4), 0, 1);
    TEST(get((int *)m.i, 23), 0, 1);
    TEST(get((int *)m.i, 24), 0, 1);
    TEST(get(m.i[0][0], -1), 0, 1);
    TEST(get(m.i[0][0], 0), 0, 0);
    TEST(get(m.i[0][0], 3), 0, 0);
    TEST(get(m.i[0][0], 4), 0, 1);
    TEST(get(m.i[0][0], 23), 0, 1);
    TEST(get(m.i[0][0], 24), 0, 1);
    TEST(get(m.i[1][0], -1), 0, 1);
    TEST(get(m.i[1][0], 0), 0, 0);
    TEST(get(m.i[1][0], 3), 0, 0);
    TEST(get(m.i[1][0], 4), 0, 1);
    TEST(get(m.i[2][0], -1), 1, 0);
    TEST(get(m.i[2][0], 0), 1, 0);
}

{
    // Anonymous structs.
    struct {
        int a;
        int b;
    } S = {11, 22};
    TUPLE T = {33, 44};
    struct {
        float x;
        int y;
    } U = {55.0, 66};
    AnonSubObj V;
    memset(&V, 0, sizeof(V));
    TEST(getAnon(&S), 0, 0);
    TEST(getAnon(&T), 1, 0);
    TEST(getAnon(&U), 1, 0);
    TEST(getAnon(&V.a), 0, 0);
    TEST(getAnon(&V.x), 1, 0);
    TEST(getAnon(&V.t), 1, 0);
    TEST(getAnon(&V.s), 1, 0);
    TEST(getAnon(&V.U), 1, 0);
    TEST(getAnon(&V.V), 1, 0);
    TEST(getAnon(V.buf), 0, 0);
    TEST(getAnon(V.buf2), 0, 1);
}

{
    // Anonymous unions.
    union {
        int i;
        float f;
    } U;
    union {
        short a;
        double d;
    } V;
    AnonSubObj A;
    memset(&V, 0, sizeof(V));
    U.i = 333;
    TEST(get(&U.i, 0), 0, 0);
    TEST(get(&U.f, 0), 0, 0);
    TEST(get(&U.i, 1), 0, 1);
    TEST(get(&U.f, 1), 0, 1);
    TEST(get(&U.i, -1), 0, 1);
    TEST(get(&U.f, -1), 0, 1);
    TEST(get((short *)&U, 0), 1, 0);
    TEST(getAnon2(&U), 0, 0);
    TEST(getAnon2(&U), 0, 0);
    TEST(getAnon2(&V), 1, 0);
    TEST(getAnon2(&V), 1, 0);
    TEST(getAnon2(&A.U), 0, 0);
    TEST(getAnon2(&A.V), 1, 0);
    TEST(getAnon2(A.buf), 0, 0);
    TEST(getAnon2(A.buf2), 0, 1);
}

{
    ENUM e = BBBB;      // Enums are just ints.
    TEST(get(&e, 0), 0, 0);
    TEST(get(&e, 1), 0, 1);
    TEST(get(&e, -1), 0, 1);
    TEST(get((int *)&e, 0), 0, 0);
    TEST(get((float *)&e, -1), 1, 0);
}

{
    ints iii = {1, 2, 3, 4};
    TEST(get(&iii, 0), 0, 0);
    TEST(get((int *)&iii, 0), 0, 0);
    TEST(get((int *)&iii, -1), 0, 1);
    TEST(get((int *)&iii, 3), 0, 0);
    TEST(get((int *)&iii, 4), 0, 1);
    TEST(get((int *)&iii+1, 3), 0, 1);
    TEST(get((floats *)&iii, 0), 1, 0);
}

{
    int _Complex iii = 3 + 4I;
    float _Complex fff = 5.2f + 3.2I;
    TEST(get(&iii, 0), 0, 0);
    TEST(get((int *)&iii , 0), 1, 0);
    TEST(get((int *)&iii + 1, 0), 1, 0);
    TEST(get(&fff, 0), 0, 0);
    TEST(get(&fff, -1), 0, 1);
    TEST(get(&fff, 1), 0, 1);
    TEST(get((float *)&fff , 0), 1, 0);
    TEST(get((float *)&fff + 1, 0), 1, 0);
    TEST(get((float *)&fff + 1, 0), 1, 0);
    TEST(get((int _Complex *)&fff + 1, 0), 1, 0);
    TEST(get((floats *)&fff, 0), 1, 0);
}

{
    // Typedef'ed pointers:
    char *ptr = nullptr;
    TEST(get(&ptr, 0), 0, 0);
    TEST(get((void **)&ptr, 0), 0, 0);
    TEST(get((voidptr_t *)&ptr, 0), 0, 0);
    TEST(get((charptr_t *)&ptr, 0), 0, 0);
    TEST(get((signedcharptr_t *)&ptr, 0), 0, 0);
    TEST(get((shortptr_t *)&ptr, 0), 0, 0);     // coerced
    TEST(get((tupleptr_t *)&ptr, 0), 0, 0);     // coerced
    TUPLE *tptr = nullptr;
    TEST(get(&tptr, 0), 0, 0);
    TEST(get((void **)&tptr, 0), 0, 0);
    TEST(get((voidptr_t *)&tptr, 0), 0, 0);
    TEST(get((charptr_t *)&tptr, 0), 0, 0);
    TEST(get((charptr_t)&tptr, 0), 0, 0);
    TEST(get((signedcharptr_t *)&tptr, 0), 0, 0);
    TEST(get((signedcharptr_t)&tptr, 0), 0, 0);
    TEST(get((shortptr_t *)&tptr, 0), 1, 0);
    TEST(get((tupleptr_t *)&tptr, 0), 0, 0);
}

{
    // stdlib++
    std::pair<int, int> p = std::make_pair(4, 2);
    TEST(sumTuple((TUPLE *)&p), 1, 0);
    std::vector<int> xs;
    for (int i = 0; i < 5; i++)
        TEST(xs.push_back(i), 0, 0);
    TEST(xs.pop_back(), 0, 0);
    std::vector<TUPLE> ys;
    for (int i = 0; i < 3; i++)
    {
        TUPLE t = {i, i};
        TEST(ys.push_back(t), 0, 0);
    }
    TEST(sumTuple(&ys[1]), 0, 0);
}

{
    // Functions:
    TEST(set(&global_func, global_func_def), 0, 0);
    int x = 3;
    float y = 4.5f;
    TEST(global_func(&x, 0), 0, 0);
    TEST(global_func((int *)&y, 0), 1, 0);
    TEST(global_func(&x, 10), 0, 1);
    // Note: not a type error because no escapes are checked:
    TEST(set(&global_func, (int (*)(int *, int))global_func_def2), 0, 0);
    TEST(global_func(&x, 0), 1, 0);
    TEST(global_func((int *)&y, 0), 0, 0);
    TEST(global_func(&x, 10), 1, 0);
}

{
    // Indirect calls
    TEST(indirectCall(getPtr, 0), 0, 0);
    TEST(indirectCall(getPtr, -1), 0, 1);
    TEST(indirectCall(getPtr, 10), 0, 1);
}

{
    // C++ pointer-to-members (treated as size_t)
    TEST(get((size_t *)&ptr2memb, 0), 0, 0);
    TEST(get((int **)&ptr2memb, 0), 1, 0);
}

{
    // Pass-by-copy
    TEST(passByCopy<int>(2), 0, 0);
    TEST(passByCopy<char>('c'), 0, 1);
    SubObjs sss;
    memset(&sss, 1, sizeof(sss));
    TEST(passByCopy(sss), 0, 0);    // buf is char[]
    Union uuu;
    memset(&uuu, 2, sizeof(uuu));
    TEST(passByCopy(uuu), 0, 0);    // int[] member
}

{
    // Global array bounds
    TEST(nop(globalArray[0]), 0, 0);
    TEST(nop(globalArray[9]), 0, 0);
}

{
    // Off-by-one bug found by ryap:
    int *q;
    p = (struct test_bug *)malloc(sizeof(struct test_bug));
    nop(p);     // Prevents transform into (int *)malloc(...)
    q = (int *)p;
    TEST(q[1] = 888, 0, 0);
    TEST(q[2] = 999, 0, 1);
    TEST(q[3] = 111, 0, 1);
    nop(q);
}

{
    // char16_t
    char16_t c;
    TEST(get(&c, 0), 0, 0);
}

{
    // Example
    S *s = new S[100];

    int *p = s[10].t.a;
    TEST(get<int>(p, 0), 0, 0);
    TEST(get<int>(p, 1), 0, 0);
    TEST(get<int>(p, 2), 0, 0);
    TEST(get<int>(p, 3), 0, 1);
    TEST(get<int>(p, -1), 0, 1);
    double *q = (double *)p;
    TEST(get<double>(q, 0), 1, 0);
    delete[] s;
    TEST(get<int>(p, 0), 1, 0);
}

{
    // Hijacking
    {
        A *a = new A(1);
        B *b = new B(1.0);
        void **buf = new void *[10];
        long long idx = (void **)b - buf;
        void *ptr;
        memcpy((void *)&ptr, (void *)a, sizeof(void *));
        TEST(overflow(buf, idx, ptr), 0, 1);
        b->g();
    }
    {
        A *a = new A(1);
        B *b = new B(1.0);
        void **buf = b->buf;
        long long idx = (void **)b - buf;
        void *ptr;
        memcpy((void *)&ptr, (void *)a, sizeof(void *));
        TEST(overflow(buf, idx, ptr), 0, 1);
        b->g();
    }
    {
        A *a = new A(1);
        B *b = new B(1.0);
        void *ptr;
        memcpy((void *)&ptr, (void *)a, sizeof(void *));
        TEST(confusion((C *)b, ptr), 1, 0);
        b->g();
    }
    {
        A *a = new A(1);
        C *c = new C;
        delete c;
        B *b = new B(1.0);
        assert((void *)c == (void *)b);
        void *ptr;
        memcpy((void *)&ptr, (void *)a, sizeof(void *));
        TEST(confusion(c, ptr), 1, 0);
        b->g();
    }
}

{
    // "this" pointer:
    int aaa[30];
    TEST(((BBB *)aaa)->method2(5), 1, 0);
    char buf[sizeof(BBB)] = {0};
    TEST(((BBB *)buf)->method2(3), 0, 0);
}

{
    // std::string
    std::string str("string ");
    TEST(str += "hello world!\n", 0, 0);
}

{
    // std::map<int>.
    const int N = 2;
    std::map<int, int> m;
    auto i = m.begin();
    TEST(nop(i->second), 1, 0);
    i = m.end();
    TEST(nop(i->second), 1, 0);
    for (int i = 0; i < N; i++)
        TEST(m.insert(std::make_pair(i, i)), 0, 0);
    for (int i = 0; i < N; i++)
    {
        std::map<int, int>::iterator j;
        TEST(j = m.find(i), 0, 0);
    }
    for (int i = 0; i < N; i++)
        TEST(m.erase(i), 0, 0);
}

{
    // std::set
    std::vector<std::set<unsigned int> > indices;
    unsigned i = id<unsigned>(0), j = id<unsigned>(0);
    std::set<unsigned int> empty;
    TEST(indices.push_back(empty), 0, 0);
    TEST(indices[i].insert(j), 0, 0);
    TEST(indices[i].clear(), 0, 0);
    TEST(indices[i].insert(j), 0, 0);
}

{
    // std::vector<float>.
    const int N = 2;
    std::vector<float> v;
    for (int i = 0; i < N; i++)
        TEST(v.push_back(i), 0, 0);
}

{
    // std::map<Big>.
    const int N = 2;
    std::map<Big, Big> m;
    for (int i = 0; i < N; i++)
        TEST(m.insert(std::make_pair(make_big(i), make_big(i+1))), 0, 0);
    for (int i = 0; i < N; i++)
    {
        std::map<Big, Big>::iterator j;
        TEST(j = m.find(make_big(i)), 0, 0);
    }
    for (int i = 0; i < N; i++)
        TEST(m.erase(make_big(i)), 0, 0);
}

{
    // std::vector<Big>.
    const int N = 2;
    std::vector<Big> v;
    for (int i = 0; i < N; i++)
        TEST(v.push_back(make_big(i)), 0, 0);
}

{
    // S. Kell's example:
    struct stuff *s = (struct stuff *)malloc(sizeof(struct stuff));
    s->x = 42.0;
    TEST(my_wmemset(s->str, (wchar_t) 0, 44), 0, 2);
    TEST(my_wmemset((wchar_t *)s, (wchar_t) 0, 44), 0, 2);
}

    freeList(xs);
    TEST(sumList(xs), 10, 0);                               // UAF errors
    ListNode<float> *zs = makeList(10, 4.0f);
    TEST(sumList(xs), 10, 0);                               // (re)UAF errors
    
    printf("\n\33[1;35mpassed\33[0m: (%zu/%zu) = \33[1m%.2f%%\33[0m\n\n",
        passed, total, ((double)passed / (double)total) * 100.0);

    return (passed == total? EXIT_SUCCESS: EXIT_FAILURE);
}

