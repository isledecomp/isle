#ifndef ACT2BRICK_H
#define ACT2BRICK_H

#include "legopathactor.h"

class Act2Brick : public LegoPathActor
{
public:
  Act2Brick();	
  virtual ~Act2Brick(); // vtable+0x0

  virtual long Tickle(); // vtable+08
  
  // VTABLE 0x100d9b60
  // SIZE 0x194
};

#endif // ACT2BRICK_H