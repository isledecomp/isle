#ifndef MXDSACTION_H
#define MXDSACTION_H

#include "mxdsobject.h"

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

  int m_unk2c;
  int m_unk30;
  int m_unk34;
  int m_unk38;
  int m_unk3c;
  int m_unk40;
  int m_unk44;
  int m_unk48;
  int m_unk4c;
  int m_unk50;
  int m_unk54;
  int m_unk58;
  int m_unk5c;
  int m_unk60;
  int m_unk64;
  int m_unk68;
  int m_unk6c;
  int m_unk70;
  int m_unk74;
  int m_unk78;
  int m_unk7c;
  int m_unk80;
  int m_unk84;
  int m_unk88;
  int m_unk8c;
  int m_unk90;
};

#endif // MXDSACTION_H
