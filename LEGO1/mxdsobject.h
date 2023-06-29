#ifndef MXDSOBJECT_H
#define MXDSOBJECT_H

#include "mxcore.h"
#include "mxatomid.h"

// VTABLE 0x100dc868
// SIZE 0x2c
class MxDSObject : public MxCore
{
public:
  __declspec(dllexport) void SetObjectName(const char *);

  MxDSObject();
  virtual ~MxDSObject() override;

  // OFFSET: LEGO1 0x100bf730
  inline virtual const char *ClassName() const override // vtable+0x0c
  {
    // 0x10101400
    return "MxDSObject";
  }

  // OFFSET: LEGO1 0x100bf740
  inline virtual MxBool IsA(const char *name) const override // vtable+0x10
  {
    return !strcmp(name, MxDSObject::ClassName()) || MxCore::IsA(name);
  }

  inline const MxAtomId& GetAtomId() { return this->m_atomId; }
  inline int GetUnknown1c() { return this->m_unk1c; }

  inline void SetUnknown1c(int p_unk1c) { this->m_unk1c = p_unk1c; }
  inline void SetUnknown24(short p_unk24) { this->m_unk24 = p_unk24; }

  // OFFSET: ISLE 0x401c40
  // OFFSET: LEGO1 0x10005530
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
