#include "bumpbouy.h"

// 0x100f0394
static char* g_bumpBouyString = "BumpBouy";

// OFFSET: LEGO1 0x100274e0 STUB
const char *BumpBouy::GetClassName() const
{
  return g_bumpBouyString;
}

// OFFSET: LEG01 0x10027500 STUB
MxBool BumpBouy::IsClass(const char *name) const
{
  // TODO

  return MxBool();
}
