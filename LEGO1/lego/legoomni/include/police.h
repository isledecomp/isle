#ifndef POLICE_H
#define POLICE_H

#include "decomp.h"
#include "legoworld.h"
#include "mxdsaction.h"
#include "policestate.h"
#include "radio.h"

// VTABLE: LEGO1 0x100d8a80
// SIZE 0x110
// Radio at 0xf8
class Police : public LegoWorld {
public:
	Police();
	virtual ~Police() override; // vtable+0x0

	virtual MxLong Notify(MxParam& p_param) override; // vtable+0x4

	// FUNCTION: LEGO1 0x1005e1e0
	inline virtual const char* ClassName() const override // vtable+0xc
	{
		// STRING: LEGO1 0x100f0450
		return "Police";
	}

	// FUNCTION: LEGO1 0x1005e1f0
	inline virtual MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, Police::ClassName()) || LegoWorld::IsA(p_name);
	}

	virtual MxResult Create(MxDSAction& p_dsAction) override; // vtable+0x18
	virtual void VTable0x50() override;                       // vtable+0x50
	virtual MxBool VTable0x5c() override;                     // vtable+0x5c
	virtual MxBool VTable0x64() override;                     // vtable+0x64
	virtual void VTable0x68(MxBool p_add) override;           // vtable+0x68

	// SYNTHETIC: LEGO1 0x1005e300
	// Police::`scalar deleting destructor'

private:
	Radio m_radio;              // 0xf8
	PoliceState* m_policeState; // 0x108
	undefined4 m_unk0x10c;      // 0x10c
};

#endif // POLICE_H
