#ifndef MXSTREAMCONTROLLER_H
#define MXSTREAMCONTROLLER_H

#include "decomp.h"
#include "mxatomid.h"
#include "mxcriticalsection.h"
#include "mxcore.h"
#include "mxdsobject.h"
#include "mxdsaction.h"
#include "mxstreamprovider.h"

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
  virtual MxResult vtable0x18(undefined4 p_unknown, undefined4 p_unknown2); //vtable+0x18
  virtual MxResult vtable0x1C(undefined4 p_unknown, undefined4 p_unknown2); //vtable+0x1c
  virtual MxResult vtable0x20(MxDSAction* action); //vtable+0x20
  virtual MxResult vtable0x24(undefined4 p_unknown); //vtable+0x24
  virtual MxResult vtable0x28(); //vtable+0x28
  virtual MxResult vtable0x2c(undefined4 p_unknown1, undefined4 p_unknow2); //vtable+0x2c
  virtual MxResult vtable0x30(undefined4 p_unknown); //vtable+0x30

  MxBool FUN_100c20d0(MxDSObject &p_obj);

  inline MxAtomId GetAtom() const { return atom; };
protected:
  MxCriticalSection m_criticalSection;
  MxAtomId atom;
  MxStreamProvider* m_provider;
  int m_unk2c;
  undefined m_unk30[0x34];
};

#endif // MXSTREAMCONTROLLER_H
