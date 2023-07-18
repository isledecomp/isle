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

// OFFSET: LEGO1 0x10038100
Pizza::~Pizza()
{
  TickleManager()->Unregister(this);
}

// OFFSET: LEGO1 0x100388a0
MxResult Pizza::Tickle()
{
  // TODO
  return SUCCESS;
}