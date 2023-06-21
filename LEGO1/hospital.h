#ifndef HOSPITAL_H
#define HOSPITAL_H

#include "legoworld.h"

class Hospital : public LegoWorld
{
public:
  Hospital();
  virtual ~Hospital(); // vtable+0x0
  
  virtual long Notify(MxParam &p); // vtable+0x04
  virtual void FUN_10076220(char param_1); // vtable+0x68

  // SIZE 0x300
};

#endif // HOSPITAL_H
