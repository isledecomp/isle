#ifndef MXDSACTION_H
#define MXDSACTION_H

#include "mxatomid.h"

class MxDSAction
{
public:
  __declspec(dllexport) MxDSAction();
  __declspec(dllexport) virtual ~MxDSAction();

  int m_unk04;
  int m_unk08;
  int m_unk0c;
  int m_unk10;
  int m_unk14;
  int m_unk18;
  int m_unk1c;
  MxAtomId m_atomId;
  unsigned short m_unk24;
  unsigned short m_unk26;
  int m_unk28;
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

  void setAtomId(MxAtomId &atomId)
  {
    this->m_atomId = atomId;
  }

};

#endif // MXDSACTION_H
