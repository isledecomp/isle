#include "mxdsmediaaction.h"

// OFFSET: LEGO1 0x100c8b40
MxDSMediaAction::MxDSMediaAction()
{
  this->m_unk98 = 0;
  this->m_unk9c = 0;
  this->m_unka0 = 0;
  this->m_unka4 = 0;
  this->m_unka8 = 0;
  *this->m_unkb4 = 0xffffffff;
  this->m_unkb0 = 0;
  *this->m_unkac = 1;
  this->SetType(MxDSType_MediaAction);
}

// OFFSET: LEGO1 0x100c8cf0
MxDSMediaAction::~MxDSMediaAction()
{
  delete this->m_unk98;
}
