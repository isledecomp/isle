#include "mxdsaction.h"

// OFFSET: LEGO1 0x100ad810
MxDSAction::MxDSAction()
{
  // TODO
  this->SetType(MxDSType_Action);
  this->m_omni = NULL;
  this->m_someTimingField = -0x80000000;
}

// OFFSET: LEGO1 0x100ada80
MxDSAction::~MxDSAction()
{
  delete this->m_unk7c;
}