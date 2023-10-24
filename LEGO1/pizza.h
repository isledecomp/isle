#ifndef PIZZA_H
#define PIZZA_H

#include "decomp.h"

#include "isleactor.h"
#include "mxcore.h"
#include "mxomni.h"
#include "mxticklemanager.h"
#include "mxtypes.h"

// VTABLE 0x100d7380
// SIZE 0x9c
class Pizza : public IsleActor
{
public:
  Pizza();
  virtual ~Pizza() override;

  virtual MxResult Tickle() override; // vtable+08

  // OFFSET: LEGO1 0x10037f90
  inline const char *ClassName() const //vtable+0c
  {
    // 0x100f038c
    return "Pizza";
  }

  // OFFSET: LEGO1 0x10037fa0
  inline MxBool IsA(const char *name) const override //vtable+10
  {
    return !strcmp(name, Pizza::ClassName()) || IsleActor::IsA(name);
  }

private:
  undefined4 m_unk78;
  undefined4 m_unk7c;
  undefined4 m_unk80;
  undefined4 m_unk84;
  undefined4 m_unk88;
  undefined4 m_unk8c;
  undefined4 m_unk90;
  undefined4 m_unk94;
  undefined m_unk98;
};

#endif // PIZZA_H
