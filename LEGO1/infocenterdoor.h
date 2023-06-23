#ifndef INFOCENTERDOOR_H
#define INFOCENTERDOOR_H

#include "legoworld.h"

class InfoCenterDoor : public LegoWorld
{
public:
  InfoCenterDoor();
  virtual ~InfoCenterDoor(); // vtable+0x0
  
  virtual long Notify(MxParam &p); // vtable+0x4

  // VTABLE 0x100d72d8
  // SIZE 0xfc
};

#endif // INFOCENTERDOOR_H
