#ifndef MXCORE_H
#define MXCORE_H

#include <string.h>

#include "mxbool.h"

class MxParam;

class MxCore
{
public:
  __declspec(dllexport) MxCore();
  __declspec(dllexport) virtual ~MxCore(); // vtable+00
  __declspec(dllexport) virtual long Notify(MxParam &p); // vtable+04
  virtual long Tickle(); // vtable+08

  // OFFSET: LEGO1 0x100144c0
  inline virtual const char *GetClassName() const { return "MxCore"; }; // vtable+0c

  // OFFSET: LEGO1 0x100140d0
  inline virtual MxBool IsClass(const char *name) const {
    return !strcmp(name, MxCore::GetClassName());
  }; // vtable+10

private:
  unsigned int m_id;

};

#endif // MXCORE_H
