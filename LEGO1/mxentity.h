#ifndef MXENTITY_H
#define MXENTITY_H

#include "decomp.h"
#include "mxatomid.h"
#include "mxcore.h"
#include "mxtypes.h"

// VTABLE 0x100d5390
// SIZE 0x68 or less
class MxEntity : public MxCore
{
public:
  MxEntity();
  virtual ~MxEntity() override;

  // OFFSET: LEGO1 0x1000c180
  inline virtual const char* ClassName() const override // vtable+0xc
  {
    // 0x100f0070
    return "MxEntity";
  }

  // OFFSET: LEGO1 0x1000c190
  inline virtual MxBool IsA(const char *name) const override // vtable+0x10
  {
    return !strcmp(name, MxEntity::ClassName()) || MxCore::IsA(name);
  }

  virtual MxResult SetEntityId(MxS32 p_id, const MxAtomId &p_atom); // vtable+0x14
private:
  MxS32 m_mxEntityId; // 0x8
  MxAtomId m_atom; // 0xc
  undefined m_unk10[76];
};

#endif // MXENTITY_H
