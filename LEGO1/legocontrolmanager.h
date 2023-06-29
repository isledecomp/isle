#ifndef LEGOCONTROLMANAGER_H
#define LEGOCONTROLMANAGER_H

#include "mxcore.h"

// VTABLE 0x100d6a80
class LegoControlManager : public MxCore
{
public:
  LegoControlManager();
  virtual ~LegoControlManager() override; // vtable+0x0

  virtual long Tickle() override; // vtable+0x8

  // OFFSET: LEGO1 0x10028cb0
  inline virtual const char *ClassName() const override // vtable+0x0c
  {
    // 0x100f31b8
    return "LegoControlManager";
  }

  // OFFSET: LEGO1 0x10028cc0
  inline virtual MxBool IsA(const char *name) const override // vtable+0x10
  {
    return !strcmp(name, LegoControlManager::ClassName()) || MxCore::IsA(name);
  }

};

#endif // LEGOCONTROLMANAGER_H
