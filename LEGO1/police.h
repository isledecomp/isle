#ifndef POLICE_H
#define POLICE_H

#include "legoworld.h"

// VTABLE 0x100d8a80
// SIZE 0x110
// Radio at 0xf8
class Police : public LegoWorld
{
public:
  Police();
  virtual ~Police() override; // vtable+0x0
  
  virtual MxLong Notify(MxParam &p) override; // vtable+0x4

  // OFFSET: LEGO1 0x1005e1e0
  inline virtual const char *ClassName() const override // vtable+0xc
  { 
    // 0x100f0450
    return "Police";
  }

  // OFFSET: LEGO1 0x1005e1f0
  inline virtual MxBool IsA(const char *name) const override // vtable+0x10
  {
    return !strcmp(name, Police::ClassName()) || LegoWorld::IsA(name);
  }
};

#endif // POLICE_H
