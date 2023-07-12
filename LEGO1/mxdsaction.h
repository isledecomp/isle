#ifndef MXDSACTION_H
#define MXDSACTION_H

#include "mxdsobject.h"
#include "mxomni.h"

// VTABLE 0x100dc098
// SIZE 0x94
class MxDSAction : public MxDSObject
{
public:
  __declspec(dllexport) MxDSAction();
  __declspec(dllexport) virtual ~MxDSAction();

  // OFFSET: LEGO1 0x100ad980
  inline virtual const char *ClassName() const override // vtable+0x0c
  {
    // 0x101013f4
    return "MxDSAction";
  }

  // OFFSET: LEGO1 0x100ad990
  inline virtual MxBool IsA(const char *name) const override // vtable+0x10
  {
    return !strcmp(name, MxDSAction::ClassName()) || MxDSObject::IsA(name);
  }
private:
  MxLong m_unk2c;
  MxLong m_unk30;
  MxLong m_unk34;
  MxLong* m_unk38;
  MxLong m_unk3c;
  MxLong m_unk40;
  MxLong m_unk44;
  MxLong m_unk48;
  MxLong m_unk4c;
  MxLong m_unk50;
  MxLong m_unk54;
  MxLong m_unk58;
  MxLong m_unk5c;
  MxLong m_unk60;
  MxLong m_unk64;
  MxLong m_unk68;
  MxLong m_unk6c;
  MxLong m_unk70;
  MxLong m_unk74;
  MxLong m_unk78;
  MxLong* m_unk7c;
  MxLong m_unk80;
  MxLong m_unk84;
  MxLong m_unk88;
  MxOmni* m_omni; // 0x8c
  MxS32 m_someTimingField; // 0x90
};

#endif // MXDSACTION_H
