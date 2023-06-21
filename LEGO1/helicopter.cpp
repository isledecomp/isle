#include "helicopter.h"

// OFFSET: LEGO1 0x100f0130
static char* g_helicopterClassName = "Helicopter";

// OFFSET: LEGO1 0x10001e60
Helicopter::Helicopter()
{
  // TODO
}

// OFFSET: LEGO1 0x10003230
Helicopter::~Helicopter()
{
  // TODO
}

// OFFSET: LEGO1 0x10003070
const char *Helicopter::GetClassName() const
{
  return g_helicopterClassName;
}

// OFFSET: LEGO1 0x10003080
MxBool Helicopter::IsClass(const char *name) const
{
  // TODO

  return MxBool();
}
