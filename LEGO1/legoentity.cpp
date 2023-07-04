#include "legoentity.h"

// OFFSET: LEGO1 0x1000c290
LegoEntity::~LegoEntity()
{
  Destroy();
}

// OFFSET: LEGO1 0x100114f0 STUB
MxLong LegoEntity::Notify(MxParam &p)
{
  // TODO

  return 0;
}

// OFFSET: LEGO1 0x10010810 STUB
void LegoEntity::Destroy()
{
  // TODO
}
