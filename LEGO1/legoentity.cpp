#include "legoentity.h"

// 0x100f0064
static char* g_legoEntityClassName = "LegoEntity";

// OFFSET: LEGO1 0x100105f0
LegoEntity::LegoEntity()
{
  // TODO
}

// OFFSET: LEGO1 0x1000c290
LegoEntity::~LegoEntity()
{
  Destroy();
}

// OFFSET: LEGO1 0x100114f0
long LegoEntity::Notify(MxParam &p)
{
  // TODO

  return 0;
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

// OFFSET: LEGO1 0x100107e0
undefined4 LegoEntity::VTable0x18(undefined4 param)
{
  // TODO

  return undefined4();
}

// OFFSET: LEGO1 0x10010810
void LegoEntity::Destroy()
{
  // TODO
}

// OFFSET: LEGO1 0x10010e10
void LegoEntity::VTable0x20(char *param)
{
  // TODO
}

// OFFSET: LEGO1 0x100108a0
void LegoEntity::VTable0x24(undefined4 param_1, undefined1 param_2, undefined1 param_3)
{
  // TODO
}

// OFFSET: LEGO1 0x10010790
void LegoEntity::VTable0x28(undefined4 param_1, undefined4 param2)
{
  // TODO
}

// OFFSET: LEGO1 0x10010650
void LegoEntity::VTable0x2c(undefined1 param)
{
  // TODO
}
