#ifndef DUNEBUGGY_H
#define DUNEBUGGY_H

#include "decomp.h"
#include "islepathactor.h"

// VTABLE 0x100d8f98
// SIZE 0x16c
class DuneBuggy : public IslePathActor
{
public:
  DuneBuggy();

  // OFFSET: LEGO1 0x10067c30
  inline virtual const char *ClassName() const override // vtable+0x0c
  {
    // 0x100f0410
    return "DuneBuggy";
  }

  // OFFSET: LEGO1 0x10067c40
  inline virtual MxBool IsA(const char *name) const override // vtable+0x10
  {
    return !strcmp(name, DuneBuggy::ClassName()) || IslePathActor::IsA(name);
  }
private:
  // TODO: Double check DuneBuggy field types
  undefined4 m_unk160;
  MxFloat m_unk164;
  undefined4 m_unk168;
};

#endif // DUNEBUGGY_H
