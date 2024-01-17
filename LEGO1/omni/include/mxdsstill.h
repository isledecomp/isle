#ifndef MXDSSTILL_H
#define MXDSSTILL_H

#include "mxdsmediaaction.h"

// VTABLE: LEGO1 0x100dce60
// SIZE 0xb8
class MxDSStill : public MxDSMediaAction {
public:
	MxDSStill();
	virtual ~MxDSStill() override;

	void CopyFrom(MxDSStill& p_dsStill);
	MxDSStill& operator=(MxDSStill& p_dsStill);

	// FUNCTION: LEGO1 0x100c9930
	inline virtual const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x101025fc
		return "MxDSStill";
	}

	// FUNCTION: LEGO1 0x100c9940
	inline virtual MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, MxDSStill::ClassName()) || MxDSMediaAction::IsA(p_name);
	}

	virtual MxDSAction* Clone() override; // vtable+2c;

	// SYNTHETIC: LEGO1 0x100c9a50
	// MxDSStill::`scalar deleting destructor'
};

#endif // MXDSSTILL_H
