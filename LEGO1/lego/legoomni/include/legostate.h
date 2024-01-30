#ifndef LEGOSTATE_H
#define LEGOSTATE_H

#include "decomp.h"
#include "lego/sources/misc/legostorage.h"
#include "mxcore.h"
#include "mxstring.h"

// VTABLE: LEGO1 0x100d46c0
// SIZE 0x08
class LegoState : public MxCore {
public:
	// FUNCTION: LEGO1 0x10005f40
	virtual ~LegoState() override {}

	// FUNCTION: LEGO1 0x100060d0
	inline virtual const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f01b8
		return "LegoState";
	}

	// FUNCTION: LEGO1 0x100060e0
	inline virtual MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, LegoState::ClassName()) || MxCore::IsA(p_name);
	}

	// FUNCTION: LEGO1 0x10005f90
	virtual MxBool VTable0x14() { return TRUE; } // vtable+0x14

	// FUNCTION: LEGO1 0x10005fa0
	virtual MxBool SetFlag() { return FALSE; } // vtable+0x18

	// FUNCTION: LEGO1 0x10005fb0
	virtual MxResult VTable0x1c(LegoFile* p_legoFile)
	{
		if (p_legoFile->IsWriteMode()) {
			p_legoFile->FUN_10006030(this->ClassName());
		}
		return SUCCESS;
	} // vtable+0x1c

	// SYNTHETIC: LEGO1 0x10006160
	// LegoState::`scalar deleting destructor'

	// SIZE 0x0c
	struct StateStruct {
		void* m_unk0x00;      // 0x00
		undefined2 m_unk0x04; // 0x04
		undefined2 m_unk0x06; // 0x06
		MxS16 m_unk0x08;      // 0x08

		StateStruct();
	};
};

#endif // LEGOSTATE_H
