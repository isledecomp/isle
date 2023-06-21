#ifndef MXDSOBJECT_H
#define MXDSOBJECT_H

#include "mxcore.h"
#include "mxatomid.h"

class MxDSObject : public MxCore
{
public:
  __declspec(dllexport) void SetObjectName(const char *);

  MxDSObject();

  inline const MxAtomId& GetAtomId() { return this->m_atomId; }
  inline int GetUnknown1c() { return this->m_unk1c; }

  inline void SetUnknown1c(int p_unk1c) { this->m_unk1c = p_unk1c; }
  inline void SetUnknown24(short p_unk24) { this->m_unk24 = p_unk24; }

  // void SetAtomId(MxAtomId p_atomId);
  inline void SetAtomId(MxAtomId p_atomId) { this->m_atomId = p_atomId; }

private:
  int m_unk08;
  short m_unk0c;
  char* m_unk10;
  int m_unk14;
  char *m_name;
  int m_unk1c;
  MxAtomId m_atomId;
  short m_unk24;
  unsigned short m_unk26;
  int m_unk28;
};

#endif // MXDSOBJECT_H
