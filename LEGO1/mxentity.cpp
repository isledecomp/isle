#include "mxentity.h"

// OFFSET: LEGO1 0x100f0070
static char* g_mxEntityClassName = "MxEntity";

// OFFSET: LEGO1 0x1000c180
const char *MxEntity::GetClassName() const
{
  return g_mxEntityClassName;
}

// OFFSET: LEG01 0x1000c190
MxBool MxEntity::IsClass(const char *name) const
{
  // TODO

  return MxBool();
}
