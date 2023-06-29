#ifndef DECOMP_H
#define DECOMP_H

#define DECOMP_STATIC_ASSERT(V) namespace { typedef int foo[(V)?1:-1]; }

typedef unsigned char undefined;
typedef unsigned short undefined2;
typedef unsigned int undefined4;

#endif // DECOMP_H
