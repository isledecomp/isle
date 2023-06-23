#ifndef LEGOCARBUILD_H
#define LEGOCARBUILD_H

#include "legoworld.h"

#ifndef undefined4
#define undefined4 int
#endif

class LegoCarBuild : public LegoWorld
{
public:
  LegoCarBuild();
  virtual ~LegoCarBuild();

  virtual long Notify(MxParam &p); // vtable+0x4
  virtual long Tickle(); // vtable+0x8
  virtual undefined4 VTable0x64(); // vtable+0x64
  virtual void VTable0x68(char param_1); // vtable+0x68
  virtual void VTable0x6c(); // vtable+0x6c
  virtual void VTable0x74(float* param_1, float* param_2); // vtable+0x74
  virtual void VTable0x78(float* param_1, float* param_2); // vtable+0x78
  virtual void VTable0x7c(float* param_1, float* param_2); // vtable+0x7c
};

#endif // LEGOCARBUILD_H
