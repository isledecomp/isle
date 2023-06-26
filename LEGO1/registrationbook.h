#ifndef REGISTRATIONBOOK_H
#define REGISTRATIONBOOK_H

#include "legoworld.h"

class RegistrationBook : public LegoWorld
{
public:
  RegistrationBook();
  virtual ~RegistrationBook(); // vtable+0x0

  virtual long Notify(MxParam &p); // vtable+0x4
  virtual void VTable0x68(char param_1); // vtable+0x68

  // VTABLE 0x100d9928
};

#endif // REGISTRATIONBOOK_H
