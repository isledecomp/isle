#include "legojetski.h"

// 0x100f053c
static char* g_legoJetskiClassName = "LegoJetski";

// OFFSET: LEGO1 0x10013e80 STUB
const char *LegoJetski::ClassName() const
{
  return g_legoJetskiClassName;
}

// OFFSET: LEGO1 0x10013ea0 STUB
MxBool LegoJetski::IsA(const char *name) const
{
  // TODO

  return MxBool();
}
