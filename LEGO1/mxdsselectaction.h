#ifndef MXDSSELECTACTION_H
#define MXDSSELECTACTION_H

#include "mxdsparallelaction.h"
#include "mxstringlist.h"
#include "decomp.h"

// VTABLE 0x100dcfc8
// SIZE 0xb0
class MxDSSelectAction : public MxDSParallelAction
{
public:
  MxDSSelectAction();
  virtual ~MxDSSelectAction() override;

  void CopyFrom(MxDSSelectAction &p_dsSelectAction);
  MxDSSelectAction &operator=(MxDSSelectAction &p_dsSelectAction);

  // OFFSET: LEGO1 0x100cb6f0
  inline virtual const char *ClassName() const override // vtable+0x0c
  {
    // 0x1010261c
    return "MxDSSelectAction";
  }

  // OFFSET: LEGO1 0x100cb700
  inline virtual MxBool IsA(const char *name) const override // vtable+0x10
  {
    return !strcmp(name, MxDSSelectAction::ClassName()) || MxDSParallelAction::IsA(name);
  }

  virtual MxU32 GetSizeOnDisk() override; // vtable+18;
  virtual void Deserialize(char **p_source, MxS16 p_unk24) override; // vtable+1c;
  virtual MxDSAction *Clone() override; // vtable+2c;

private:
  MxString m_unk0x9c;
  MxStringList *m_unk0xac;
};

#endif // MXDSSELECTACTION_H
