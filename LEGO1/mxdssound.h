#ifndef MXDSSOUND_H
#define MXDSSOUND_H

#include "mxdsmediaaction.h"
#include "mxtypes.h"

// VTABLE 0x100dcdd0
// SIZE 0xc0
class MxDSSound : public MxDSMediaAction
{
public:
  MxDSSound();
  virtual ~MxDSSound() override;

  // OFFSET: LEGO1 0x100c9330
  inline virtual const char *ClassName() const override // vtable+0x0c
  {
    // 0x101025e4
    return "MxDSSound";
  }

  // OFFSET: LEGO1 0x100c9340
  inline virtual MxBool IsA(const char *name) const override // vtable+0x10
  {
    return !strcmp(name, MxDSSound::ClassName()) || MxDSMediaAction::IsA(name);
  }
private:
  MxS32 m_unkb8;
  MxLong m_lastField; // 0xbc
};


#endif // MXDSSOUND_H
