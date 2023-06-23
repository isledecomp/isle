#include "mxentity.h"

#include "mxatomid.h"

// 0x100f0070
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

// OFFSET: LEGO1 0x10001070
undefined4 MxEntity::VTable0x14(undefined4 param_1, MxAtomId *param_2)
{
  // TODO

  return undefined4();
}
