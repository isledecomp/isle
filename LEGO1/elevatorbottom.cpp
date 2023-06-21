#include "elevatorbottom.h"

// OFFSET: LEGO1 0x100f04ac
static char* g_elevatorBottomClassName = "ElevatorBottom";

// OFFSET: LEGO1 0x10017e90
ElevatorBottom::ElevatorBottom()
{
  // TODO
}

// OFFSET: LEGO1 0x10017f20
const char *ElevatorBottom::GetClassName() const
{
  return g_elevatorBottomClassName;
}

// OFFSET: LEGO1 0x10017f30
MxBool ElevatorBottom::IsClass(const char *name) const
{
  return MxBool();
}
