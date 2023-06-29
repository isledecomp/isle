#ifndef MXCORE_H
#define MXCORE_H

#include <string.h>

#include "mxtypes.h"

class MxParam;

// VTABLE 0x100dc0f8
// SIZE 0x8
class MxCore
{
public:
  __declspec(dllexport) MxCore();
  __declspec(dllexport) virtual ~MxCore(); // vtable+00
  __declspec(dllexport) virtual long Notify(MxParam &p); // vtable+04
  virtual long Tickle(); // vtable+08

  // OFFSET: LEGO1 0x100144c0
  inline virtual const char *ClassName() const // vtable+0c
  {
    // 0x100f007c
    return "MxCore";
  }

  // OFFSET: LEGO1 0x100140d0
  inline virtual MxBool IsA(const char *name) const // vtable+10
  {
    return !strcmp(name, MxCore::ClassName());
  }

private:
  unsigned int m_id;

};

#endif // MXCORE_H
