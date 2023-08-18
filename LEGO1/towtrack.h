#ifndef TOWTRACK_H
#define TOWTRACK_H

#include "decomp.h"
#include "islepathactor.h"

// VTABLE 0x100d7ee0
// SIZE 0x180
class TowTrack : public IslePathActor
{
public:
  TowTrack();

  // OFFSET: LEGO1 0x1004c7c0
  inline virtual const char *ClassName() const override // vtable+0x0c
  {
    // 0x100f03b8
    return "TowTrack";
  }

  // OFFSET: LEGO1 0x1004c7d0
  inline virtual MxBool IsA(const char *name) const override // vtable+0x10
  {
    return !strcmp(name, TowTrack::ClassName()) || IslePathActor::IsA(name);
  }

private:
  // TODO: TowTrack field types
  undefined m_unk160[0x4];
  MxS32 m_unk164;
  MxS16 m_unk168;
  MxS16 m_unk16a;
  MxS16 m_unk16c;
  MxS16 m_unk16e;
  MxS32 m_unk170;
  MxS32 m_unk174;
  MxFloat m_unk178;
};


#endif // TOWTRACK_H
