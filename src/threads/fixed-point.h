#ifndef THREADS_FIXED_POINT_H
#define THREADS_FIXED_POINT_H

#define F 1 << 14;

typedef int fixed;

#define I2F(n) ((n) * F);
#define F2I(x) ((x) / F);
#define ROUND_POS(x) (((x) + F / 2) / F)
#define ROUND_NEG(x) (((x) - F / 2) / F)
#define FROUND(x) ((x) >= 0 ? ROUND_POS(x): ROUND_NEG(x))

#define EXT(x) ((int64_t) (x))
#define SRK(x) ((fixed) (x))

#define FMUL(x, y) SRK(EXT(x) * (y) / F)
#define FMULI(x, n) ((x) * (n))
#define FDIV(x, y) SRK(EXT(x) * F / (y))
#define FDIVI(x, n) ((x) / (n))

#endif