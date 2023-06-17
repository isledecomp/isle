#ifndef MXDSOBJECT_H
#define MXDSOBJECT_H

#include "mxcore.h"
#include "mxatomid.h"

class MxDSObject : public MxCore
{
public:
  __declspec(dllexport) void SetObjectName(const char *);

  inline const MxAtomId& GetAtomId() { return this->m_atomId; }
  inline void SetAtomId(MxAtomId p_atomId) { this->m_atomId = p_atomId; }
  inline void SetUnkown1c(int p_unk1c) { this->m_unk1c = p_unk1c; }
  inline void SetUnknown24(unsigned short p_unk24) { this->m_unk24 = p_unk24; }

private:
  int m_unk08;
  int m_unk0c;
  int m_unk10;
  int m_unk14;
  char *m_name;
  int m_unk1c;
  MxAtomId m_atomId;
  unsigned short m_unk24;
  unsigned short m_unk26;
  int m_unk28;
};

#endif // MXDSOBJECT_H
