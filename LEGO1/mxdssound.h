#ifndef MXDSSOUND_H
#define MXDSSOUND_H

#include "mxdsmediaaction.h"

// VTABLE 0x100dcdd0
// SIZE 0xc0
class MxDSSound : public MxDSMediaAction
{
public:
  MxDSSound();
  virtual ~MxDSSound() override;

  void CopyFrom(MxDSSound &p_dsSound);
  MxDSSound &operator=(MxDSSound &p_dsSound);

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

  virtual MxU32 GetSizeOnDisk(); // vtable+18;
  virtual void Deserialize(char **p_source, MxS16 p_unk24); // vtable+1c;
  virtual MxDSAction *Clone(); // vtable+2c;

private:
  MxU32 m_sizeOnDisk;
  MxS32 m_volume; // 0xbc
};

#endif // MXDSSOUND_H
