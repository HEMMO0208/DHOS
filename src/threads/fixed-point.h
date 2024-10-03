#ifndef THREADS_FIXED_POINT_H
#define THREADS_FIXED_POINT_H

typedef int fixed;
#define F (1 << 14)

// #define I2F(n) ((n) * F)
// #define F2I(x) ((x) / F)
// #define ROUND_POS(x) (((x) + F / 2) / F)
// #define ROUND_NEG(x) (((x) - F / 2) / F)
// #define FROUND(x) ((x) >= 0 ? ROUND_POS(x): ROUND_NEG(x))

// #define FMUL(x, y) SRK(EXT(x) * (y) / F)
// #define FMULI(x, n) ((x) * (n))
// #define FDIV(x, y) SRK(EXT(x) * F / (y))
// #define FDIVI(x, n) ((x) / (n))

fixed I2F(int n);
int F2I(fixed x);
int FROUND(fixed x);
fixed FADD(fixed x, fixed y);
fixed FADDI(fixed x, int n);
fixed FMUL(fixed x, fixed y);
fixed FMULI(fixed x, int n);
fixed FDIV(fixed x, fixed y);
fixed FDIVI(fixed x, int n);

#endif