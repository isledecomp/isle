#ifndef HOSPITAL_H
#define HOSPITAL_H

#include "legoworld.h"

// VTABLE 0x100d9730
// SIZE 0x12c
class Hospital : public LegoWorld
{
public:
  Hospital();
  virtual ~Hospital() override; // vtable+0x0
  
  virtual MxLong Notify(MxParam &p) override; // vtable+0x04

  // OFFSET: LEGO1 0x100746b0
  inline virtual const char *ClassName() const override // vtable+0x0c
  {
    // 0x100f0490
    return "Hospital";
  }

  // OFFSET: LEGO1 0x100746c0
  inline virtual MxBool IsA(const char *name) const override // vtable+0x10
  {
    return !strcmp(name, Hospital::ClassName()) || LegoWorld::IsA(name);
  }

};

#endif // HOSPITAL_H
