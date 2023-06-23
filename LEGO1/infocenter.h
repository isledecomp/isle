#ifndef INFOCENTER_H
#define INFOCENTER_H

#include "legoworld.h"

class InfoCenter : public LegoWorld
{
public:
  InfoCenter();
  virtual ~InfoCenter();

  virtual long Notify(MxParam &p); // vtable+0x4
  virtual long Tickle(); // vtable+0x8

  // VTABLE 0x100d9338
  // SIZE 0x1d8
};

#endif // INFOCENTER_H
