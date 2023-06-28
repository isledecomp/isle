#ifndef BUMPBOUY_H
#define BUMPBOUY_H

#include "mxbool.h"

class BumpBouy
{
public:
  virtual const char* ClassName() const; // vtable+0xc
  virtual MxBool IsA(const char *name) const; // vtable+0x10
};

#endif // BUMPBOUY_H
