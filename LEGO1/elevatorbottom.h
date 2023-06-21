#ifndef ELEVATORBOTTOM_H
#define ELEVATORBOTTOM_H

#include "legoworld.h"

class ElevatorBottom : public LegoWorld
{
public:
  ElevatorBottom();

  virtual const char* GetClassName() const;
  virtual MxBool IsClass(const char *name) const;
};

#endif // ELEVATORBOTTOM_H
