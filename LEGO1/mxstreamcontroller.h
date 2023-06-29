#ifndef MXSTREAMCONTROLLER_H
#define MXSTREAMCONTROLLER_H

#include "mxatomid.h"
#include "mxcore.h"

// VTABLE 0x100dc968
class MxStreamController : public MxCore
{
public:

  // OFFSET: LEGO1 0x100c0f10
  inline virtual const char *ClassName() const override // vtable+0xc
  {
    // 0x10102130
    return "MxStreamController";
  }

  // OFFSET: LEGO1 0x100c0f20
  inline virtual MxBool IsA(const char *name) const override // vtable+0x10
  {
    return !strcmp(name, MxStreamController::ClassName()) || MxCore::IsA(name);
  }

  int m_unk00;
  int m_unk04;
  int m_unk08;
  int m_unk0c;
  int m_unk10;
  int m_unk14;
  int m_unk18;
  int m_unk1c;
  int m_unk20;
  MxAtomId atom;
  int m_unk28;
  int m_unk2c;
};

#endif // MXSTREAMCONTROLLER_H
