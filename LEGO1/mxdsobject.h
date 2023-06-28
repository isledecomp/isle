#ifndef MXDSOBJECT_H
#define MXDSOBJECT_H

#include "mxcore.h"
#include "mxatomid.h"

class MxDSObject : public MxCore
{
public:
  __declspec(dllexport) void SetObjectName(const char *p_objectName);

  MxDSObject();
  virtual ~MxDSObject();

  MxDSObject &operator=(MxDSObject &p_dsObject);
  void CopyFrom(MxDSObject &p_dsObject);

    // OFFSET: LEGO1 0x100bf730
  inline virtual const char *ClassName() const { return "MxDSObject"; }; // vtable+0c

  // OFFSET: LEGO1 0x100bf740
  inline virtual MxBool IsA(const char *name) const { return !strcmp(name, MxDSObject::ClassName()) || MxCore::IsA(name); }; // vtable+10;

  virtual int unk14(); // vtable+14;
  virtual unsigned int CalculateUnk08(); // vtable+18;
  virtual void Parse(char **p_source, unsigned short p_unk24); // vtable+1c;

  void SetSourceName(const char *p_sourceName);

  inline const MxAtomId& GetAtomId() { return this->m_atomId; }
  inline int GetUnknown1c() { return this->m_unk1c; }

  inline void SetUnknown1c(int p_unk1c) { this->m_unk1c = p_unk1c; }
  inline void SetUnknown24(short p_unk24) { this->m_unk24 = p_unk24; }

  // OFFSET: ISLE 0x401c40
  // OFFSET: LEGO1 0x10005530
  inline void SetAtomId(MxAtomId p_atomId) { this->m_atomId = p_atomId; }

private:
  unsigned int m_unk08;
  short m_unk0c;
  char* m_sourceName;
  int m_unk14;
  char *m_objectName;
  int m_unk1c;
  MxAtomId m_atomId;
  short m_unk24;
  unsigned short m_unk26;
  int m_unk28;
};

#endif // MXDSOBJECT_H
