#ifndef MXDSMEDIAACTION_H
#define MXDSMEDIAACTION_H

#include "decomp.h"
#include "mxdsaction.h"

// VTABLE 0x100dcd40
// SIZE 0xb8
class MxDSMediaAction : public MxDSAction
{
public:
  MxDSMediaAction();
  virtual ~MxDSMediaAction() override;

  void CopyFrom(MxDSMediaAction &p_dsMediaAction);
  MxDSMediaAction &operator=(MxDSMediaAction &p_dsMediaAction);

  // OFFSET: LEGO1 0x100c8be0
  inline virtual const char *ClassName() const override // vtable+0x0c
  {
    // 0x100f7624
    return "MxDSMediaAction";
  }

  // OFFSET: LEGO1 0x100c8bf0
  inline virtual MxBool IsA(const char *name) const override // vtable+0x10
  {
    return !strcmp(name, MxDSMediaAction::ClassName()) || MxDSAction::IsA(name);
  }

  virtual MxU32 GetSizeOnDisk(); // vtable+18;
  virtual void Deserialize(char **p_source, MxS16 p_unk24); // vtable+1c;

  void CopyMediaSrcPath(const char *p_mediaSrcPath);

  inline MxS32 const GetMediaFormat() { return this->m_mediaFormat; }
private:
  MxU32 m_sizeOnDisk;
  char *m_mediaSrcPath;
  undefined4 m_unk9c;
  undefined4 m_unka0;
  MxS32 m_framesPerSecond;
  MxS32 m_mediaFormat;
  MxS32 m_paletteManagement;
  MxLong m_sustainTime;
  undefined4 m_unkb4;
};

#endif // MXDSMEDIAACTION_H
