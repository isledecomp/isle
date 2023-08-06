#include "mxdsaction.h"

#include <float.h>
#include <limits.h>

// OFFSET: LEGO1 0x100ad810
MxDSAction::MxDSAction()
{
  this->m_flags = 32;
  this->m_startTime = INT_MIN;
  this->m_unk7c = NULL;
  this->m_unk80 = 0;
  this->m_duration = INT_MIN;
  this->m_loopCount = -1;

  this->SetType(MxDSType_Action);

  {
    float value = FLT_MAX;
    this->m_location.EqualsScalar(&value);
  }

  {
    float value = FLT_MAX;
    this->m_direction.EqualsScalar(&value);
  }

  {
    float value = FLT_MAX;
    this->m_up.EqualsScalar(&value);
  }

  this->m_unk84 = 0;
  this->m_unk88 = 0;
  this->m_omni = NULL;
  this->m_someTimingField = INT_MIN;
}

// OFFSET: LEGO1 0x100ada80
MxDSAction::~MxDSAction()
{
  delete this->m_unk7c;
}
