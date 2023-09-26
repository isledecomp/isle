#ifndef MXSTREAMCONTROLLER_H
#define MXSTREAMCONTROLLER_H

#include "decomp.h"
#include "mxatomid.h"
#include "mxcriticalsection.h"
#include "mxcore.h"
#include "mxdsobject.h"

// VTABLE 0x100dc968
// SIZE 0x64
class MxStreamController : public MxCore
{
public:
  MxStreamController();

  virtual ~MxStreamController() override; // vtable+0x0

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

  virtual MxResult Open(const char *p_filename); // vtable+0x14

  MxBool FUN_100c20d0(MxDSObject &p_obj);

  MxCriticalSection m_criticalSection;
  MxAtomId atom;
  int m_unk28;
  int m_unk2c;
  undefined m_unk30[0x34];
};

#endif // MXSTREAMCONTROLLER_H
