#include "pizza.h"

// OFFSET: LEGO1 0x10037ef0
Pizza::Pizza()
{
  // FIXME: This inherits from LegoActor, probably why this isn't matching
  this->m_unk80 = 0;
  this->m_unk84 = 0;
  this->m_unk88 = 0;
  this->m_unk8c = -1;
  this->m_unk98 = 0;
  this->m_unk90 = 0x80000000;
}

// OFFSET: LEGO1 0x1002c7cf STUB
Pizza* Unk1002c7b0(undefined4 p_param)
{
  // FIXME: Stub, a switch function. I think it adjusts some metadata based on a state. We'll understand this more once we get into Pizzeria
  return new Pizza;
}

// OFFSET: LEGO1 0x10038100
Pizza::~Pizza()
{
  // FIXME: some vtable call from tickle manager, unimplemented atm
  delete this;
}


// OFFSET: LEGO1 0x100388a0 STUB
Pizza* Unk100388a0(undefined4* p_param)
{
  // FIXME: Stub, Looks like this function adjusts (or makes?) a new Pizza based on the game state, perhaps PizzaMissionState?
  return new Pizza;
}