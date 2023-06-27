#ifndef LEGOENTITY_H
#define LEGOENTITY_H

#include "mxentity.h"

#ifndef undefined1
#define undefined1 char
#endif

class LegoEntity : public MxEntity
{
public:
  LegoEntity();
  __declspec(dllexport) virtual ~LegoEntity(); // vtable+0x0

  virtual long Notify(MxParam &p); // vtable+0x4

  // OFFSET: LEGO1 0x1000c2f0
  inline const char *LegoEntity::GetClassName() const // vtable+0xc
  {
    return "LegoEntity";
  }

  // OFFSET: LEGO1 0x1000c300
  inline MxBool LegoEntity::IsClass(const char *name) const // vtable+0x10
  {
    return !strcmp(name, LegoEntity::GetClassName()) || MxEntity::IsClass(name);
  }

  virtual undefined4 VTable0x18(undefined4 param); // vtable+0x18
  virtual void Destroy(); // vtable+0x1c
  virtual void VTable0x20(char* param); // vtable+0x20
  virtual void VTable0x24(undefined4 param_1, undefined1 param_2, undefined1 param_3); // vtable+0x24
  virtual void VTable0x28(undefined4 param_1, undefined4 param2); // vtable+0x28
  virtual void VTable0x2c(undefined1 param); // vtable+0x2c
  virtual void VTable0x30(undefined4 param); // vtable+0x30
  virtual void VTable0x34(undefined1 param); // vtable+0x34
  virtual void VTable0x38(); // vtable+0x38
  virtual void VTable0x3c(); // vtable+0x3c
  virtual void VTable0x40(); // vtable+0x40
  virtual void VTable0x44(); // vtable+0x44
  virtual void VTable0x48(undefined4 param); // vtable+0x48
  virtual void VTable0x4c(); // vtable+0x4c

};

#endif // LEGOENTITY_H
