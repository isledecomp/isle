#ifndef REGISTRATIONBOOK_H
#define REGISTRATIONBOOK_H

#include "legoworld.h"

// VTABLE 0x100d9928
// SIZE 0x2d0
class RegistrationBook : public LegoWorld
{
public:
  RegistrationBook();
  virtual ~RegistrationBook() override; // vtable+0x0

  virtual MxLong Notify(MxParam &p) override; // vtable+0x4

};

#endif // REGISTRATIONBOOK_H
