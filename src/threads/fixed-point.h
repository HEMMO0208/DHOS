#ifndef THREADS_FIXED_POINT_H
#define THREADS_FIXED_POINT_H

typedef int fixed;
#define F (1 << 14)

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