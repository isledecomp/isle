#ifndef MXDSEVENT_H
#define MXDSEVENT_H

#include "mxdsmediaaction.h"

class MxDSEvent : public MxDSMediaAction {
public:
	MxDSEvent();
	virtual ~MxDSEvent() override;

	void CopyFrom(MxDSEvent& p_dsEvent);
	MxDSEvent& operator=(MxDSEvent& p_dsEvent);

	// FUNCTION: LEGO1 0x100c9660
	inline virtual const char* ClassName() const override // vtable+0x0c
	{
		// 0x101025f0
		return "MxDSEvent";
	}

	// FUNCTION: LEGO1 0x100c9670
	inline virtual MxBool IsA(const char* name) const override // vtable+0x10
	{
		return !strcmp(name, MxDSEvent::ClassName()) || MxDSMediaAction::IsA(name);
	}

	virtual MxDSAction* Clone() override; // vtable+2c;
};

#endif // MXDSEVENT_H
