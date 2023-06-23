#include "helicopter.h"

// 0x100f0130
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

// OFFSET: LEGO1 0x10003ee0
void Helicopter::VTable0x70(float param_1)
{
  // TODO
}

// OFFSET:LEGO1 0x10003360
void Helicopter::VTable0xe4()
{
  // TODO
}
