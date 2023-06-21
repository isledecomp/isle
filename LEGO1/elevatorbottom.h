#ifndef ELEVATORBOTTOM_H
#define ELEVATORBOTTOM_H

#include "legoworld.h"

class ElevatorBottom : public LegoWorld
{
public:
  ElevatorBottom();
  virtual ~ElevatorBottom();

  virtual const char* GetClassName() const;
  virtual MxBool IsClass(const char *name) const;

  virtual int FUN_10017f10() { return 1; } // Return is undefined
  virtual void FUN_100182c0(char param_1);
};

#endif // ELEVATORBOTTOM_H
