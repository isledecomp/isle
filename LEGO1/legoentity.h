#ifndef LEGOENTITY_H
#define LEGOENTITY_H

#include "mxentity.h"
#include "mxvector.h"
#include "extra.h"
#include "decomp.h"
#include "mxdsobject.h"

// VTABLE 0x100d4858
// SIZE 0x68 (probably)
class LegoEntity : public MxEntity
{
public:
  // Inlined at 0x100853f7
  inline LegoEntity()
  {
    // TODO
  }

  __declspec(dllexport) virtual ~LegoEntity() override; // vtable+0x0

  virtual MxLong Notify(MxParam &p) override; // vtable+0x4

  // OFFSET: LEGO1 0x1000c2f0
  inline const char *ClassName() const override // vtable+0xc
  {
    // 0x100f0064
    return "LegoEntity";
  }

  // OFFSET: LEGO1 0x1000c300
  inline MxBool IsA(const char *name) const override // vtable+0x10
  {
    return !strcmp(name, LegoEntity::ClassName()) || MxEntity::IsA(name);
  }

  virtual MxResult InitFromMxDSObject(MxDSObject &p_dsObject); // vtable+0x18
  virtual void Destroy(MxBool p_fromDestructor); // vtable+0x1c
  virtual void ParseAction(char *); // vtable+0x20
  virtual void VTable0x24(); // vtable+0x24
  virtual void VTable0x28(); // vtable+0x28
  virtual void VTable0x2c(); // vtable+0x2c
  // OFFSET: LEGO1 0x10001090
  virtual void VTable0x30(undefined4 p_unk50) { m_unk50 = p_unk50; } // vtable+0x30
  virtual void VTable0x34(); // vtable+0x34
  virtual void VTable0x38(); // vtable+0x38
  virtual void VTable0x3c(); // vtable+0x3c
  virtual void VTable0x40(); // vtable+0x40
  virtual void VTable0x44(); // vtable+0x44
  virtual void VTable0x48(); // vtable+0x48
  virtual void VTable0x4c(); // vtable+0x4c

protected:
  void Reset();
  void AddToCurrentWorld();

  undefined m_unk10;
  undefined m_unk11;
  MxVector3Data m_vec1; // 0x14
  MxVector3Data m_vec2; // 0x28
  MxVector3Data m_vec3; // 0x3c
  undefined4 m_unk50;
  undefined4 m_unk54;
  undefined m_unk58;
  undefined m_unk59;
  // For tokens from the extra string that look like this:
  // "Action:openram;\lego\scripts\Race\CarRaceR;0"
  ExtraActionType m_actionType; // 0x5c
  char *m_actionArgString; // 0x60
  MxS32 m_actionArgNumber; // 0x64
};

#endif // LEGOENTITY_H
