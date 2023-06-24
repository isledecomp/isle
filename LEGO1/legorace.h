#ifndef LEGORACE_H
#define LEGORACE_H

#include "legoworld.h"

class LegoRace : public LegoWorld
{
public:
  LegoRace();
  virtual ~LegoRace(); // vtable+0x0

  virtual long Notify(MxParam &p); // vtable+0x4
};

#endif // LEGORACE_H