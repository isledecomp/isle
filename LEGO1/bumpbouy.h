#ifndef BUMPBOUY_H
#define BUMPBOUY_H

#include "mxbool.h"

class BumpBouy
{
  virtual const char* GetClassName() const;
  virtual MxBool IsClass(const char *name) const;
};

#endif // BUMPBOUY_H
