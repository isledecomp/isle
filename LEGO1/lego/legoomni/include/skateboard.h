#ifndef SKATEBOARD_H
#define SKATEBOARD_H

#include "decomp.h"
#include "islepathactor.h"

// VTABLE: LEGO1 0x100d55f0
// SIZE 0x168
class SkateBoard : public IslePathActor {
public:
	SkateBoard();

	// FUNCTION: LEGO1 0x1000fdd0
	inline const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f041c
		return "SkateBoard";
	}

	// FUNCTION: LEGO1 0x1000fde0
	inline MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, SkateBoard::ClassName()) || IslePathActor::IsA(p_name);
	}

	MxResult Create(MxDSAction& p_dsAction) override;            // vtable+0x18
	MxU32 VTable0xcc() override;                                 // vtable+0xcc
	MxU32 VTable0xd0() override;                                 // vtable+0xd0
	MxU32 VTable0xd4(LegoControlManagerEvent& p_param) override; // vtable+0xd4
	void VTable0xe4() override;                                  // vtable+0xe4

	// SYNTHETIC: LEGO1 0x1000ff60
	// SkateBoard::`scalar deleting destructor'

private:
	// TODO: SkateBoard types
	undefined m_unk0x160;
	undefined m_unk0x161[0x7];
};

#endif // SKATEBOARD_H
