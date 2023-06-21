#include "legoentity.h"

// OFFSET: LEG01 0x100f0064
static char* g_legoEntityClassName = "LegoEntity";

// OFFSET: LEGO1 0x100105f0
LegoEntity::LegoEntity()
{
  // TODO
}

// OFFSET: LEGO1 0x1000c2f0
const char *LegoEntity::GetClassName() const
{
  return g_legoEntityClassName;
}

// OFFSET: LEGO1 0x1000c300
MxBool LegoEntity::IsClass(const char *name) const
{
  // TODO

  return MxBool();
}
