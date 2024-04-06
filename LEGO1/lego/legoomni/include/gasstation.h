#ifndef GASSTATION_H
#define GASSTATION_H

#include "decomp.h"
#include "gasstationstate.h"
#include "legogamestate.h"
#include "legoworld.h"
#include "mxstillpresenter.h"
#include "radio.h"

// VTABLE: LEGO1 0x100d4650
// SIZE 0x128
class GasStation : public LegoWorld {
public:
	GasStation();
	~GasStation() override; // vtable+0x00

	MxLong Notify(MxParam& p_param) override; // vtable+0x04
	MxResult Tickle() override;               // vtable+0x08

	// FUNCTION: LEGO1 0x10004780
	inline const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f0168
		return "GasStation";
	}

	// FUNCTION: LEGO1 0x10004790
	inline MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, GasStation::ClassName()) || LegoWorld::IsA(p_name);
	}

	MxResult Create(MxDSAction& p_dsAction) override;             // vtable+0x18
	void ReadyWorld() override;                                   // vtable+0x50
	MxBool VTable0x5c() override;                                 // vtable+0x5c
	MxBool VTable0x64() override;                                 // vtable+0x64
	void Enable(MxBool p_enable) override;                        // vtable+0x68
	virtual MxLong HandleClick(LegoControlManagerEvent& p_param); // vtable+0x6c

	inline void PlayAction(MxU32 p_objectId);

	// SYNTHETIC: LEGO1 0x100048a0
	// GasStation::`scalar deleting destructor'

private:
	MxLong HandleEndAction(MxEndActionNotificationParam& p_param);
	MxLong HandleKeyPress(MxS8 p_key);
	MxLong HandleButtonDown(LegoControlManagerEvent& p_param);

	MxS16 m_currentActorId;             // 0xf8
	undefined2 m_unk0xfa;               // 0xfa
	LegoGameState::Area m_destLocation; // 0xfc
	GasStationState* m_state;           // 0x100
	undefined2 m_unk0x104;              // 0x104
	undefined2 m_unk0x106;              // 0x106
	MxStillPresenter* m_trackLedBitmap; // 0x108
	MxLong m_unk0x10c;                  // 0x10c
	MxLong m_trackLedTimer;             // 0x110
	MxBool m_unk0x114;                  // 0x114
	MxBool m_unk0x115;                  // 0x115
	Radio m_radio;                      // 0x118
};

#endif // GASSTATION_H
