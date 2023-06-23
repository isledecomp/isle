#ifndef POLICE_H
#define POLICE_H

#include "legoworld.h"

class Police : public LegoWorld
{
public:
  Police();
  virtual ~Police(); // vtable+0x0
  
  virtual long Notify(MxParam &p); // vtable+0x4
  

  // VTABLE 0x100d8a80
  // SIZE 0x110
  // Radio at 0xf8
};

#endif // POLICE_H