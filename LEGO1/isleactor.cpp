#include "isleactor.h"

// 0x100f07dc
static char* g_isleActorClassName = "IsleActor";

// OFFSET: LEGO1 0x100d5178 STUB
long IsleActor::Notify(MxParam &p)
{
  // TODO

  return 0;
}

// OFFSET: LEGO1 0x1000e660 STUB
const char *IsleActor::GetClassName() const
{
  return g_isleActorClassName;
}

// OFFSET: LEGO1 0x1000e670 STUB
MxBool IsleActor::IsClass(const char *name) const
{
  // TODO

  return MxBool();
}
