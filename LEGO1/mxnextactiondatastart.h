#ifndef MXNEXTACTIONDATASTART_H
#define MXNEXTACTIONDATASTART_H

#include "mxcore.h"

// VTABLE 0x100dc9a0
class MxNextActionDataStart : public MxCore
{
  // OFFSET: LEGO1 0x100c1990
  virtual ~MxNextActionDataStart() override;
  {

  }
  inline virtual const char *ClassName() const override // vtable+0x0c
  {
    // 0x100c1900
    return "MxNextActionDataStart";
  }

  // OFFSET: LEGO1 0x100c1910
  inline virtual MxBool IsA(const char *p_name) const override // vtable+0x10
  {
    return !strcmp(p_name, MxNextActionDataStart::ClassName()) || MxCore::IsA(p_name);
  }
};

#endif // MXNEXTACTIONDATASTART_H
