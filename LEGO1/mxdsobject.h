#ifndef MXDSOBJECT_H
#define MXDSOBJECT_H

#include "decomp.h"

#include "mxcore.h"
#include "mxatomid.h"
#include "mxdstypes.h"

// VTABLE 0x100dc868
// SIZE 0x2c
class MxDSObject : public MxCore
{
public:
  MxDSObject();
  virtual ~MxDSObject() override;

  void CopyFrom(MxDSObject &p_dsObject);
  MxDSObject &operator=(MxDSObject &p_dsObject);

  __declspec(dllexport) void SetObjectName(const char *p_objectName);
  void SetSourceName(const char *p_sourceName);

  // OFFSET: LEGO1 0x100bf730
  inline virtual const char *ClassName() const override { return "MxDSObject"; }; // vtable+0c

  // OFFSET: LEGO1 0x100bf740
  inline virtual MxBool IsA(const char *name) const override { return !strcmp(name, MxDSObject::ClassName()) || MxCore::IsA(name); }; // vtable+10;

  virtual undefined4 unk14(); // vtable+14;
  virtual MxU32 CalculateUnk08(); // vtable+18;
  virtual void Parse(char **p_source, MxS16 p_unk24); // vtable+1c;

  inline const MxAtomId& GetAtomId() { return this->m_atomId; }
  inline undefined4 GetUnknown1c() { return this->m_unk1c; }

  inline void SetUnknown1c(undefined4 p_unk1c) { this->m_unk1c = p_unk1c; }
  inline void SetUnknown24(MxS16 p_unk24) { this->m_unk24 = p_unk24; }

  // OFFSET: ISLE 0x401c40
  // OFFSET: LEGO1 0x10005530
  inline void SetAtomId(MxAtomId p_atomId) { this->m_atomId = p_atomId; }

protected:
  inline void SetType(MxDSType p_type) { this->m_type = p_type; }

private:
  MxU32 m_unk08;
  MxU16 m_type;
  char* m_sourceName;
  undefined4 m_unk14;
  char *m_objectName;
  undefined4 m_unk1c;
  MxAtomId m_atomId;
  MxS16 m_unk24;
  undefined4 m_unk28;
};

#endif // MXDSOBJECT_H
