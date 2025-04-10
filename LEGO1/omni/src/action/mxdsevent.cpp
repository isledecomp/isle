#include "mxdsevent.h"

DECOMP_SIZE_ASSERT(MxDSEvent, 0xb8)

// FUNCTION: LEGO1 0x100c95f0
// FUNCTION: BETA10 0x1015d2e5
MxDSEvent::MxDSEvent()
{
	m_type = e_event;
}

// FUNCTION: LEGO1 0x100c97a0
// FUNCTION: BETA10 0x1015d35d
MxDSEvent::~MxDSEvent()
{
}

// FUNCTION: LEGO1 0x100c97f0
// FUNCTION: BETA10 0x1015d3c5
void MxDSEvent::CopyFrom(MxDSEvent& p_dsEvent)
{
}

// FUNCTION: BETA10 0x1015d3dd
MxDSEvent::MxDSEvent(MxDSEvent& p_dsEvent) : MxDSMediaAction(p_dsEvent)
{
	CopyFrom(p_dsEvent);
}

// FUNCTION: LEGO1 0x100c9800
// FUNCTION: BETA10 0x1015d45e
MxDSEvent& MxDSEvent::operator=(MxDSEvent& p_dsEvent)
{
	if (this == &p_dsEvent) {
		return *this;
	}

	MxDSMediaAction::operator=(p_dsEvent);
	CopyFrom(p_dsEvent);
	return *this;
}

// FUNCTION: LEGO1 0x100c9830
// FUNCTION: BETA10 0x1015d4a5
MxDSAction* MxDSEvent::Clone()
{
	MxDSEvent* clone = new MxDSEvent();

	if (clone) {
		*clone = *this;
	}

	return clone;
}
