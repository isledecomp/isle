#include "legojetski.h"

// 0x100f053c
static char* g_legoJetskiClassName = "LegoJetski";

// OFFSET: LEGO1 0x10013e80 STUB
const char *LegoJetski::GetClassName() const
{
  return g_legoJetskiClassName;
}

// OFFSET: LEGO1 0x10013ea0 STUB
MxBool LegoJetski::IsClass(const char *name) const
{
  // TODO

  return MxBool();
}
