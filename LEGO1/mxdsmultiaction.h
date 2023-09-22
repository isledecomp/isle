#ifndef MXDSMULTIACTION_H
#define MXDSMULTIACTION_H

#include "mxdsaction.h"
#include "mxdsactionlist.h"

// VTABLE 0x100dcef0
// SIZE 0x9c
class MxDSMultiAction : public MxDSAction
{
public:
  MxDSMultiAction();
  virtual ~MxDSMultiAction() override;

  void CopyFrom(MxDSMultiAction &p_dsMultiAction);
  MxDSMultiAction &operator=(MxDSMultiAction &p_dsMultiAction);

  // OFFSET: LEGO1 0x100c9f50
  inline virtual const char *ClassName() const override // vtable+0x0c
  {
    // 0x10101dbc
    return "MxDSMultiAction";
  }

  // OFFSET: LEGO1 0x100c9f60
  inline virtual MxBool IsA(const char *name) const override // vtable+0x10
  {
    return !strcmp(name, MxDSMultiAction::ClassName()) || MxDSAction::IsA(name);
  }

  virtual undefined4 unk14(); // vtable+14;
  virtual MxU32 GetSizeOnDisk(); // vtable+18;
  virtual void Deserialize(char **p_source, MxS16 p_unk24); // vtable+1c;
  virtual void SetAtomId(MxAtomId p_atomId); // vtable+20;
  virtual MxDSAction *Clone(); // vtable+2c;
  virtual void MergeFrom(MxDSAction &p_dsAction); // vtable+30;
  virtual MxBool HasId(MxU32 p_objectId); // vtable+34;
  virtual void SetSomeTimingField(MxLong p_someTimingField); // vtable+38;

private:
  MxU32 m_sizeOnDisk;
  MxDSActionList *m_actions;
};

#endif // MXDSMULTIACTION_H
