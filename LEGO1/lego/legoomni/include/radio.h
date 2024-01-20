#ifndef RADIO_H
#define RADIO_H

#include "mxcore.h"
#include "radiostate.h"

// VTABLE: LEGO1 0x100d6d10
class Radio : public MxCore {
public:
	Radio();
	virtual ~Radio() override;

	virtual MxLong Notify(MxParam& p_param) override; // vtable+0x04

	// FUNCTION: LEGO1 0x1002c8e0
	inline virtual const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f328c
		return "Radio";
	}

	// FUNCTION: LEGO1 0x1002c8f0
	inline virtual MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, Radio::ClassName()) || MxCore::IsA(p_name);
	}

	// SYNTHETIC: LEGO1 0x1002c970
	// Radio::`scalar deleting destructor'

private:
	RadioState* m_state; // 0x08
	MxBool m_unk0xc;     // 0x0c

	void CreateRadioState();
};

#endif // RADIO_H
