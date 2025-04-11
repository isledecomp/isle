#ifndef MXDSEVENT_H
#define MXDSEVENT_H

#include "mxdsmediaaction.h"

// VTABLE: LEGO1 0x100dce18
// VTABLE: BETA10 0x101c2bb0
class MxDSEvent : public MxDSMediaAction {
public:
	MxDSEvent();
	MxDSEvent(MxDSEvent& p_dsEvent);
	~MxDSEvent() override;

	void CopyFrom(MxDSEvent& p_dsEvent);
	MxDSEvent& operator=(MxDSEvent& p_dsEvent);

	// FUNCTION: LEGO1 0x100c9660
	// FUNCTION: BETA10 0x1015da10
	const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x101025f0
		return "MxDSEvent";
	}

	// FUNCTION: LEGO1 0x100c9670
	// FUNCTION: BETA10 0x1015da30
	MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, MxDSEvent::ClassName()) || MxDSMediaAction::IsA(p_name);
	}

	MxDSAction* Clone() override; // vtable+0x2c

	// SYNTHETIC: LEGO1 0x100c9780
	// SYNTHETIC: BETA10 0x1015da90
	// MxDSEvent::`scalar deleting destructor'
};

#endif // MXDSEVENT_H
