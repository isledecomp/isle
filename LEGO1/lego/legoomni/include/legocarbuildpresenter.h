#ifndef LEGOCARBUILDPRESENTER_H
#define LEGOCARBUILDPRESENTER_H

#include "anim/legoanim.h"
#include "legoanimpresenter.h"

// VTABLE: LEGO1 0x100d99e0
// VTABLE: BETA10 0x101bb988
// SIZE 0x150
class LegoCarBuildAnimPresenter : public LegoAnimPresenter {
public:
	// SIZE 0x0c
	struct UnknownListEntry {
		LegoChar* m_unk0x00;    // 0x00
		LegoChar* m_unk0x04;    // 0x04
		undefined m_unk0x08[4]; // 0x08
	};

	LegoCarBuildAnimPresenter();
	~LegoCarBuildAnimPresenter() override; // vtable+0x00

	// FUNCTION: BETA10 0x10073290
	static const char* HandlerClassName()
	{
		// STRING: LEGO1 0x100f05ec
		return "LegoCarBuildAnimPresenter";
	}

	// FUNCTION: LEGO1 0x10078510
	// FUNCTION: BETA10 0x10073260
	const char* ClassName() const override // vtable+0x0c
	{
		return HandlerClassName();
	}

	// FUNCTION: LEGO1 0x10078520
	MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, LegoCarBuildAnimPresenter::ClassName()) || LegoAnimPresenter::IsA(p_name);
	}

	void ReadyTickle() override;     // vtable+0x18
	void StreamingTickle() override; // vtable+0x20
	void RepeatingTickle() override; // vtable+0x24
	void EndAction() override;       // vtable+0x40
	void PutFrame() override;        // vtable+0x6c

	void FUN_10079160();
	void RotateAroundYAxis(MxFloat p_angle);
	MxBool FUN_10079c30(const LegoChar* p_name);
	MxBool FUN_10079ca0(const LegoChar* p_name);
	MxBool FUN_10079cf0(const LegoChar* p_string);

	// FUNCTION: BETA10 0x10070180
	void SetUnknown0xbc(undefined2 p_unk0xbc) { m_unk0xbc = p_unk0xbc; }

	MxBool StringEndsOnYOrN(const LegoChar* p_string);

	const BoundingSphere& FUN_10079e20();

	// SYNTHETIC: LEGO1 0x10078660
	// LegoCarBuildAnimPresenter::`scalar deleting destructor'

private:
	undefined2 m_unk0xbc;         // 0xbc
	MxS16 m_unk0xbe;              // 0xbe
	MxS16 m_unk0xc0;              // 0xc0
	LegoAnimNodeData* m_unk0xc4;  // 0xc4
	LegoAnim m_unk0xc8;           // 0xc8
	MxMatrix m_unk0xe0;           // 0xe0
	UnknownListEntry* m_unk0x128; // 0x128
	MxFloat m_unk0x12c;           // 0x12c
	undefined4 m_unk0x130;        // 0x130
	undefined4 m_unk0x134;        // 0x134
	undefined4 m_unk0x138;        // 0x138
	undefined4 m_unk0x13c;        // 0x13c
	LegoEntity* m_unk0x140;       // 0x140
	MxS32 m_unk0x144;             // 0x144
	MxS32 m_unk0x148;             // 0x148
	undefined* m_unk0x14c;        // 0x14c
};

#endif // LEGOCARBUILDPRESENTER_H
