#ifndef LEGOPATHACTOR_H
#define LEGOPATHACTOR_H

#include "legoactor.h"
#include "mxtypes.h"

// VTABLE 0x100d6e28
// SIZE 0x154 (from inlined construction at 0x1000a346)
class LegoPathActor : public LegoActor
{
public:
  LegoPathActor();

  virtual ~LegoPathActor() override;

  // OFFSET: LEGO1 0x1000c430
  inline const char *ClassName() const override // vtable+0xc
  {
    // 0x100f0114
    return "LegoPathActor";
  }

  // OFFSET: LEGO1 0x1000c440
  inline MxBool IsA(const char *name) const override // vtable+0x10
  {
    return !strcmp(name, LegoPathActor::ClassName()) || LegoActor::IsA(name);
  }

  virtual void VTable0x68(); // vtable+0x68
  virtual void VTable0x6c(); // vtable+0x6c
  virtual void VTable0x70(); // vtable+0x70
  virtual void VTable0x74(); // vtable+0x74
  virtual void VTable0x78(); // vtable+0x78
  virtual void VTable0x7c(); // vtable+0x7c
  virtual void VTable0x80(); // vtable+0x80
  virtual void VTable0x84(); // vtable+0x84
  virtual void VTable0x88(); // vtable+0x88
  virtual void VTable0x8c(); // vtable+0x8c
  virtual void VTable0x90(); // vtable+0x90
  virtual void VTable0x94(); // vtable+0x94
  virtual void VTable0x98(); // vtable+0x98
  virtual void VTable0x9c(); // vtable+0x9c
  virtual void VTable0xa0(); // vtable+0xa0
  virtual void VTable0xa4(); // vtable+0xa4
  virtual void VTable0xa8(); // vtable+0xa8
  virtual void VTable0xac(); // vtable+0xac
  virtual void VTable0xb0(); // vtable+0xb0
  virtual void VTable0xb4(); // vtable+0xb4
  virtual void VTable0xb8(); // vtable+0xb8
  virtual void VTable0xbc(); // vtable+0xbc
  virtual void VTable0xc0(); // vtable+0xc0
  virtual void VTable0xc4(); // vtable+0xc4
  virtual void VTable0xc8(); // vtable+0xc8
  
protected:
  // TODO: the types
  undefined unk78[0xc4];
  MxFloat m_unk13c;
  MxS32 m_unk140;
  MxS32 m_unk144;
  undefined m_unk148;
  MxS32 m_unk14c;
  MxFloat m_unk150;
};

#endif // LEGOPATHACTOR_H
