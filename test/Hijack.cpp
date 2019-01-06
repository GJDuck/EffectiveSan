/*
 *        __  __           _   _           ____
 *   ___ / _|/ _| ___  ___| |_(_)_   _____/ ___|  __ _ _ __
 *  / _ \ |_| |_ / _ \/ __| __| \ \ / / _ \___ \ / _` | '_ \
 * |  __/  _|  _|  __/ (__| |_| |\ V /  __/___) | (_| | | | |
 *  \___|_| |_|  \___|\___|\__|_| \_/ \___|____/ \__,_|_| |_|
 *
 * Proof-of-concept control-flow hijacking (vptr overwrite) example.
 *
 * If the example is working it should print "HIJACKED" 4 times.
 *
 * EffectiveSan should detect:
 * - 2x type error;
 * - 1x bounds overflow; and
 * - 1x sub-object bounds overflow.
 */

#include <cassert>
#include <cstdio>
#include <cstring>

#define NOINLINE    __attribute__((__noinline__))

class A
{
    private:

        int x;

    public:

        A(int y) : x(y) { }
        
        virtual void f(void)
        {
            printf("HIJACKED!\n");
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
            printf("OK\n");
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

int main(void)
{
    // OBJECT BOUNDS OVERFLOW
    {
        A *a = new A(1);
        B *b = new B(1.0);
        void **buf = new void *[10];
        long long idx = (void **)b - buf;
        void *ptr;
        memcpy((void *)&ptr, (void *)a, sizeof(void *));
        overflow(buf, idx, ptr);
        b->g();
    }

    // SUB-OBJECT BOUNDS OVERFLOW (UNDERFLOW)
    {
        A *a = new A(1);
        B *b = new B(1.0);
        void **buf = b->buf;
        long long idx = (void **)b - buf;
        void *ptr;
        memcpy((void *)&ptr, (void *)a, sizeof(void *));
        overflow(buf, idx, ptr);
        b->g();
    }

    // TYPE CONFUSION
    {
        A *a = new A(1);
        B *b = new B(1.0);
        void *ptr;
        memcpy((void *)&ptr, (void *)a, sizeof(void *));
        confusion((C *)b, ptr);
        b->g();
    }

    // USE-AFTER-FREE
    // Note: This will manifest as a type error.
    {
        A *a = new A(1);
        C *c = new C;
        delete c;
        B *b = new B(1.0);
        assert((void *)c == (void *)b);
        void *ptr;
        memcpy((void *)&ptr, (void *)a, sizeof(void *));
        confusion(c, ptr);
        b->g();
    }

    return 0;
}

