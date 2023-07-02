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
  
};

#endif // POLICE_H
