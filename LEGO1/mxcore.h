#ifndef MXCORE_H
#define MXCORE_H

#include "mxbool.h"

class MxParam;

class MxCore
{
public:
  __declspec(dllexport) MxCore();
  __declspec(dllexport) virtual ~MxCore(); // vtable+00
  __declspec(dllexport) virtual long Notify(MxParam &p); // vtable+04
  virtual long Tickle(); // vtable+08
  virtual const char *GetClassName() const; // vtable+0c
  virtual MxBool IsClass(const char *name) const; // vtable+10

private:
  unsigned int m_id;

};

#endif // MXCORE_H
