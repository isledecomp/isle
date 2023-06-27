#include "legoanimactor.h"

// 0x100f057c
static char* g_legoAnimActorClassName = "LegoAnimActor";

// OFFSET: LEGO1 0x1000fb90 STUB
const char* GetClassNameInternal()
{
  return g_legoAnimActorClassName;
}

// OFFSET: LEGO1 0x1000fb90 STUB
const char *LegoAnimActor::GetClassName() const
{
  return GetClassNameInternal();
}

// OFFSET: LEGO1 0x1000fbb0 STUB
MxBool LegoAnimActor::IsClass(const char *name) const
{
  // TODO

  return MxBool();
}
