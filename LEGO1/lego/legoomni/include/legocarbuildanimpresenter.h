#ifndef LEGOCARBUILDANIMPRESENTER_H
#define LEGOCARBUILDANIMPRESENTER_H

#include "legoanimpresenter.h"

// VTABLE: LEGO1 0x100d99e0
// SIZE 0x150
class LegoCarBuildAnimPresenter : public LegoAnimPresenter {
public:
	LegoCarBuildAnimPresenter();
	~LegoCarBuildAnimPresenter() override; // vtable+0x00

	// FUNCTION: LEGO1 0x10078510
	inline const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f05ec
		return "LegoCarBuildAnimPresenter";
	}

	// FUNCTION: LEGO1 0x10078520
	inline MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, LegoCarBuildAnimPresenter::ClassName()) || LegoAnimPresenter::IsA(p_name);
	}

	void ReadyTickle() override;     // vtable+0x18
	void StreamingTickle() override; // vtable+0x20
	void RepeatingTickle() override; // vtable+0x24
	void EndAction() override;       // vtable+0x40
	void PutFrame() override;        // vtable+0x6c

	// SYNTHETIC: LEGO1 0x10078660
	// LegoCarBuildAnimPresenter::`scalar deleting destructor'

private:
	undefined2 m_unk0xbc;  // 0xbc
	undefined2 m_unk0xbe;  // 0xbe
	undefined2 m_unk0xc0;  // 0xc0
	undefined4 m_unk0xc4;  // 0xc4
	LegoAnim m_unk0xc8;    // 0xc8
	MxMatrix m_unk0xe0;    // 0xe0
	undefined4 m_unk0x128; // 0x128
	undefined4 m_unk0x12c; // 0x12c
	undefined4 m_unk0x130; // 0x130
	undefined4 m_unk0x134; // 0x134
	undefined4 m_unk0x138; // 0x138
	undefined4 m_unk0x13c; // 0x13c
	undefined4 m_unk0x140; // 0x140
	MxS32 m_unk0x144;      // 0x144
	MxS32 m_unk0x148;      // 0x148
	undefined4 m_unk0x14c; // 0x14c
};

#endif // LEGOCARBUILDANIMPRESENTER_H
