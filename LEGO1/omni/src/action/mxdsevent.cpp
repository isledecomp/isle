#include "mxdsevent.h"

DECOMP_SIZE_ASSERT(MxDSEvent, 0xb8)

// FUNCTION: LEGO1 0x100c95f0
MxDSEvent::MxDSEvent()
{
	this->SetType(e_event);
}

// FUNCTION: LEGO1 0x100c97a0
MxDSEvent::~MxDSEvent()
{
}

// FUNCTION: LEGO1 0x100c97f0
void MxDSEvent::CopyFrom(MxDSEvent& p_dsEvent)
{
}

// FUNCTION: LEGO1 0x100c9800
MxDSEvent& MxDSEvent::operator=(MxDSEvent& p_dsEvent)
{
	if (this == &p_dsEvent)
		return *this;

	MxDSMediaAction::operator=(p_dsEvent);
	this->CopyFrom(p_dsEvent);
	return *this;
}

// FUNCTION: LEGO1 0x100c9830
MxDSAction* MxDSEvent::Clone()
{
	MxDSEvent* clone = new MxDSEvent();

	if (clone)
		*clone = *this;

	return clone;
}
