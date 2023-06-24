#ifndef LEGOENTITY_H
#define LEGOENTITY_H

#include "mxentity.h"

#ifndef undefined4
#define undefined4 int
#endif

#ifndef undefined1
#define undefined1 char
#endif

class LegoEntity : public MxEntity
{
public:
  LegoEntity();
  __declspec(dllexport) virtual ~LegoEntity(); // vtable+0x0

  virtual long Notify(MxParam &p); // vtable+0x4
  virtual const char* GetClassName() const; // vtable+0xc
  virtual MxBool IsClass(const char *name) const; // vtable+0x10

  virtual undefined4 VTable0x18(undefined4 param); // vtable+0x18
  virtual void Destroy(); // vtable+0x1c
  virtual void VTable0x20(char* param); // vtable+0x20
  virtual void VTable0x24(undefined4 param_1, undefined1 param_2, undefined1 param_3); // vtable+0x24
  virtual void VTable0x28(undefined4 param_1, undefined4 param2); // vtable+0x28
  virtual void VTable0x2c(undefined1 param); // vtable+0x2c
};

#endif // LEGOENTITY_H
