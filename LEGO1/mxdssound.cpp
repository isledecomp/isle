#include "mxdssound.h"

// OFFSET: LEGO1 0x100c92c0
MxDSSound::MxDSSound()
{
  this->m_lastField = 0x4f;
  this->SetType(MxDSType_Sound);
}

// OFFSET: LEGO1 0x100c9470
MxDSSound::~MxDSSound()
{
}
