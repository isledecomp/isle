#ifndef LEGORACE_H
#define LEGORACE_H

#include "decomp.h"
#include "legogamestate.h"
#include "legostate.h"
#include "legoworld.h"
#include "mxrect32.h"
#include "mxtypes.h"

class Act1State;
class LegoEventNotificationParam;
class LegoPathActor;
class MxEndActionNotificationParam;
class MxNotificationParam;
class LegoPathStructEvent;

// VTABLE: LEGO1 0x100d5e30
// SIZE 0x2c
class RaceState : public LegoState {
public:
	// SIZE 0x06
	struct Entry {
	public:
		inline MxS16 GetUnknown0x02() { return m_unk0x02; }
		inline MxS16 GetHighScore() { return m_score; }

		// TODO: Possibly private
		MxU8 m_id;       // 0x00
		MxS16 m_unk0x02; // 0x02
		MxS16 m_score;   // 0x04
	};

	RaceState();

	// FUNCTION: LEGO1 0x10016010
	inline const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f07d0
		return "RaceState";
	}

	// FUNCTION: LEGO1 0x10016020
	inline MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, RaceState::ClassName()) || LegoState::IsA(p_name);
	}

	MxResult Serialize(LegoFile* p_legoFile) override; // vtable+0x1c

	Entry* GetState(MxU8 p_id);

	inline undefined4 GetUnknown0x28() { return m_unk0x28; }

	// SYNTHETIC: LEGO1 0x1000f6f0
	// RaceState::~RaceState

	// SYNTHETIC: LEGO1 0x100160d0
	// RaceState::`scalar deleting destructor'

	// TODO: Most likely getters/setters are not used according to BETA.

	Entry m_state[5];     // 0x08
	undefined4 m_unk0x28; // 0x28
};

// VTABLE: LEGO1 0x100d5db0
// SIZE 0x144
class LegoRace : public LegoWorld {
public:
	LegoRace();
	~LegoRace() override; // vtable+0x00

	MxLong Notify(MxParam& p_param) override; // vtable+0x04

	// FUNCTION: BETA10 0x100a8970
	static const char* HandlerClassName()
	{
		// STRING: LEGO1 0x100f07c4
		return "LegoRace";
	}

	// FUNCTION: LEGO1 0x10015ba0
	// FUNCTION: BETA10 0x100a8940
	inline const char* ClassName() const override // vtable+0x0c
	{
		return HandlerClassName();
	}

	// FUNCTION: LEGO1 0x10015bb0
	inline MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, LegoRace::ClassName()) || LegoWorld::IsA(p_name);
	}

	MxResult Create(MxDSAction& p_dsAction) override; // vtable+0x18

	// FUNCTION: LEGO1 0x1000dae0
	MxBool VTable0x5c() override { return TRUE; } // vtable+0x5c

	MxBool Escape() override;                                      // vtable+0x64
	void Enable(MxBool p_enable) override;                         // vtable+0x68
	virtual MxLong HandleClick(LegoEventNotificationParam&) = 0;   // vtable+0x6c
	virtual MxLong HandlePathStruct(LegoPathStructEvent&);         // vtable+0x70
	virtual MxLong HandleEndAction(MxEndActionNotificationParam&); // vtable+0x74

	// FUNCTION: LEGO1 0x1000dab0
	virtual MxLong HandleType0Notification(MxNotificationParam&) { return 0; } // vtable+0x78

	// STUB: LEGO1 0x1000dac0
	virtual void VTable0x7c(undefined4, undefined4) {} // vtable+0x7c

	// SYNTHETIC: LEGO1 0x10015cc0
	// LegoRace::`scalar deleting destructor'

protected:
	undefined4 m_unk0xf8;               // 0xf8
	undefined4 m_unk0xfc;               // 0xfc
	undefined4 m_unk0x100;              // 0x100
	undefined4 m_unk0x104;              // 0x104
	undefined4 m_unk0x108;              // 0x108
	undefined4 m_unk0x10c;              // 0x10c
	undefined4 m_unk0x110;              // 0x110
	undefined4 m_unk0x114;              // 0x114
	undefined4 m_unk0x118;              // 0x118
	LegoGameState::Area m_destLocation; // 0x11c
	LegoPathActor* m_pathActor;         // 0x120
	Act1State* m_act1State;             // 0x124
	undefined4 m_unk0x128;              // 0x128
	undefined4 m_unk0x12c;              // 0x12c
	MxRect32 m_unk0x130;                // 0x130
	undefined4 m_unk0x140;              // 0x140
};

#endif // LEGORACE_H
