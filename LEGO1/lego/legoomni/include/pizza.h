#ifndef PIZZA_H
#define PIZZA_H

#include "decomp.h"
#include "isleactor.h"

class Act1State;
class PizzaMissionState;
class SkateBoard;

// VTABLE: LEGO1 0x100d7380
// SIZE 0x9c
class Pizza : public IsleActor {
public:
	Pizza();
	~Pizza() override;

	MxResult Tickle() override; // vtable+0x08

	// FUNCTION: LEGO1 0x10037f90
	inline const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f038c
		return "Pizza";
	}

	// FUNCTION: LEGO1 0x10037fa0
	inline MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, Pizza::ClassName()) || IsleActor::IsA(p_name);
	}

	MxResult Create(MxDSAction& p_dsAction) override;                   // vtable+0x18
	undefined4 HandleClick() override;                                  // vtable+0x68
	undefined4 HandleEndAction(MxEndActionNotificationParam&) override; // vtable+0x74
	undefined4 VTable0x80(MxParam&) override;                           // vtable+0x80

	void CreateState();
	void FUN_10038220(MxU32 p_objectId);
	void FUN_100382b0();
	void FUN_10038380();

	inline void SetSkateboard(SkateBoard* p_skateboard) { m_skateboard = p_skateboard; }

	// SYNTHETIC: LEGO1 0x100380e0
	// Pizza::`scalar deleting destructor'

private:
	PizzaMissionState* m_state; // 0x7c
	undefined4 m_unk0x80;       // 0x80
	SkateBoard* m_skateboard;   // 0x84
	Act1State* m_act1state;     // 0x88
	undefined4 m_unk0x8c;       // 0x8c
	undefined4 m_unk0x90;       // 0x90
	undefined4 m_unk0x94;       // 0x94
	undefined m_unk0x98;        // 0x98
};

#endif // PIZZA_H
