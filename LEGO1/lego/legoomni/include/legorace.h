#ifndef LEGORACE_H
#define LEGORACE_H

#include "decomp.h"
#include "legogamestate.h"
#include "legoraceactor.h"
#include "legoracemap.h"
#include "legostate.h"
#include "legoworld.h"
#include "mxgeometry.h"
#include "mxtypes.h"

class Act1State;
class LegoControlManagerNotificationParam;
class LegoPathActor;
class MxEndActionNotificationParam;
class MxNotificationParam;
class LegoPathStructNotificationParam;

// VTABLE: LEGO1 0x100d5e30
// VTABLE: BETA10 0x101be270
// SIZE 0x2c
class RaceState : public LegoState {
public:
	// SIZE 0x06
	struct Entry {
	public:
		// FUNCTION: LEGO1 0x10016000
		Entry()
		{
			m_id = 0;
			m_unk0x02 = 0;
			m_score = 0;
		}

		MxS16 GetUnknown0x02() { return m_unk0x02; }

		// FUNCTION: BETA10 0x10088970
		MxS16 GetHighScore() { return m_score; }

		// FUNCTION: BETA10 0x100c96f0
		MxResult Serialize(LegoStorage* p_storage)
		{
			if (p_storage->IsReadMode()) {
				p_storage->ReadU8(m_id);
				p_storage->ReadS16(m_unk0x02);
				p_storage->ReadS16(m_score);
			}
			else if (p_storage->IsWriteMode()) {
				p_storage->WriteU8(m_id);
				p_storage->WriteS16(m_unk0x02);
				p_storage->WriteS16(m_score);
			}
			else {
				return FAILURE;
			}

			return SUCCESS;
		}

		// TODO: Possibly private
		MxU8 m_id;       // 0x00
		MxS16 m_unk0x02; // 0x02
		MxS16 m_score;   // 0x04
	};

	RaceState();

	// FUNCTION: LEGO1 0x10016010
	// FUNCTION: BETA10 0x100a9040
	const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f07d0
		// STRING: BETA10 0x101f1d20
		return "RaceState";
	}

	// FUNCTION: LEGO1 0x10016020
	// FUNCTION: BETA10 0x100a8fd0
	MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, RaceState::ClassName()) || LegoState::IsA(p_name);
	}

	MxResult Serialize(LegoStorage* p_storage) override; // vtable+0x1c

	Entry* GetState(MxU8 p_id);

	// SYNTHETIC: LEGO1 0x1000f6f0
	// RaceState::~RaceState

	// SYNTHETIC: LEGO1 0x100160d0
	// RaceState::`scalar deleting destructor'

	// TODO: Most likely getters/setters are not used according to BETA.

	Entry m_state[5];     // 0x08
	undefined4 m_unk0x28; // 0x28
};

// VTABLE: LEGO1 0x100d5db0
// VTABLE: BETA10 0x101be1e0
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

	MxResult Create(MxDSAction& p_dsAction) override; // vtable+0x18

	virtual MxLong HandleControl(LegoControlManagerNotificationParam&) = 0; // vtable+0x6c

	// FUNCTION: LEGO1 0x10015b70
	virtual MxLong HandlePathStruct(LegoPathStructNotificationParam&) { return 0; } // vtable+0x70

	// FUNCTION: LEGO1 0x10015b80
	virtual MxLong HandleEndAction(MxEndActionNotificationParam&) { return 0; } // vtable+0x74

	// FUNCTION: LEGO1 0x10015b90
	MxBool Escape() override { return FALSE; } // vtable+0x64

	// FUNCTION: LEGO1 0x10015ba0
	// FUNCTION: BETA10 0x100a8940
	const char* ClassName() const override // vtable+0x0c
	{
		return HandlerClassName();
	}

	// FUNCTION: LEGO1 0x10015bb0
	// FUNCTION: BETA10 0x100a88d0
	MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, LegoRace::ClassName()) || LegoWorld::IsA(p_name);
	}

	// FUNCTION: LEGO1 0x1000dab0
	virtual MxLong HandleType0Notification(MxNotificationParam&) { return 0; } // vtable+0x78

	// FUNCTION: LEGO1 0x1000dac0
	// FUNCTION: BETA10 0x100a87d0
	virtual void VTable0x7c(LegoRaceMap* p_map, MxU32 p_index) // vtable+0x7c
	{
		m_maps[p_index] = p_map;
	}

	// FUNCTION: LEGO1 0x1000dae0
	MxBool EnabledAfterDestruction() override { return TRUE; } // vtable+0x5c

	void Enable(MxBool p_enable) override; // vtable+0x68

	// SYNTHETIC: LEGO1 0x10015cc0
	// LegoRace::`scalar deleting destructor'

protected:
	MxS32 m_unk0xf8;                    // 0xf8
	MxS32 m_unk0xfc;                    // 0xfc
	MxS32 m_unk0x100;                   // 0x100
	MxS32 m_unk0x104;                   // 0x104
	MxS32 m_unk0x108;                   // 0x108
	MxS32 m_unk0x10c;                   // 0x10c
	LegoRaceMap* m_maps[3];             // 0x110
	LegoGameState::Area m_destLocation; // 0x11c
	LegoPathActor* m_pathActor;         // 0x120
	Act1State* m_act1State;             // 0x124
	MxStillPresenter* m_unk0x128;       // 0x128
	MxStillPresenter* m_unk0x12c;       // 0x12c
	MxRect32 m_unk0x130;                // 0x130
	RaceState* m_raceState;             // 0x140
};

#endif // LEGORACE_H
