#ifndef ISLEPATHACTOR_H
#define ISLEPATHACTOR_H

#include "legogamestate.h"
#include "legopathactor.h"
#include "mxtypes.h"

class LegoControlManagerEvent;
class LegoEndAnimNotificationParam;
class LegoWorld;
class MxType19NotificationParam;

// VTABLE: LEGO1 0x100d4398
// SIZE 0x160
class IslePathActor : public LegoPathActor {
public:
	// SIZE 0x38
	struct SpawnLocation {
		SpawnLocation() {}

		// FUNCTION: LEGO1 0x1001b1b0
		SpawnLocation(
			LegoGameState::Area p_area,
			MxAtomId* p_script,
			MxS32 p_entityId,
			const char* p_key,
			undefined2 p_unk0x20,
			float p_unk0x24,
			undefined2 p_unk0x28,
			float p_unk0x2c,
			undefined4 p_unk0x30,
			JukeboxScript::Script p_music
		)
		{
			m_area = p_area;
			m_script = p_script;
			m_entityId = p_entityId;
			strcpy(m_key, p_key);
			m_unk0x20 = p_unk0x20;
			m_unk0x24 = p_unk0x24;
			m_unk0x28 = p_unk0x28;
			m_unk0x2c = p_unk0x2c;
			m_unk0x30 = p_unk0x30;
			m_music = p_music;
		}

		// FUNCTION: LEGO1 0x1001b230
		SpawnLocation& operator=(const SpawnLocation& p_container)
		{
			m_area = p_container.m_area;
			m_script = p_container.m_script;
			m_entityId = p_container.m_entityId;
			strcpy(m_key, p_container.m_key);
			m_unk0x20 = p_container.m_unk0x20;
			m_unk0x24 = p_container.m_unk0x24;
			m_unk0x28 = p_container.m_unk0x28;
			m_unk0x2c = p_container.m_unk0x2c;
			m_unk0x30 = p_container.m_unk0x30;
			m_music = p_container.m_music;
			return *this;
		}

	private:
		LegoGameState::Area m_area;    // 0x00
		MxAtomId* m_script;            // 0x04
		MxS32 m_entityId;              // 0x08
		char m_key[20];                // 0x0c
		undefined2 m_unk0x20;          // 0x20
		float m_unk0x24;               // 0x24
		undefined2 m_unk0x28;          // 0x28
		float m_unk0x2c;               // 0x2c
		undefined4 m_unk0x30;          // 0x30
		JukeboxScript::Script m_music; // 0x34
	};

	IslePathActor();

	// FUNCTION: LEGO1 0x10002e10
	inline ~IslePathActor() override { IslePathActor::Destroy(TRUE); }

	MxLong Notify(MxParam& p_param) override; // vtable+0x04

	// FUNCTION: LEGO1 0x10002ea0
	inline const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f0104
		return "IslePathActor";
	}

	// FUNCTION: LEGO1 0x10002eb0
	inline MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, IslePathActor::ClassName()) || LegoPathActor::IsA(p_name);
	}

	MxResult Create(MxDSAction& p_dsAction) override; // vtable+0x18
	void Destroy(MxBool p_fromDestructor) override;   // vtable+0x1c

	// FUNCTION: LEGO1 0x10002e70
	virtual MxU32 VTable0xcc() { return 0; } // vtable+0xcc

	// FUNCTION: LEGO1 0x10002df0
	virtual MxU32 VTable0xd0() { return 0; } // vtable+0xd0

	// FUNCTION: LEGO1 0x10002e80
	virtual MxU32 VTable0xd4(LegoControlManagerEvent&) { return 0; } // vtable+0xd4

	// FUNCTION: LEGO1 0x10002e90
	virtual MxU32 VTable0xd8(LegoEndAnimNotificationParam&) { return 0; } // vtable+0xd8

	// FUNCTION: LEGO1 0x10002e00
	virtual MxU32 VTable0xdc(MxType19NotificationParam&) { return 0; } // vtable+0xdc

	virtual void VTable0xe0();                                  // vtable+0xe0
	virtual void VTable0xe4();                                  // vtable+0xe4
	virtual void VTable0xe8(LegoGameState::Area, MxBool, MxU8); // vtable+0xe8
	virtual void VTable0xec(MxMatrix p_transform, LegoPathBoundary* p_boundary, MxBool p_reset);

	// SYNTHETIC: LEGO1 0x10002ff0
	// IslePathActor::`scalar deleting destructor'

	inline void SetWorld(LegoWorld* p_world) { m_world = p_world; }
	inline LegoWorld* GetWorld() { return m_world; }

	void FUN_1001b660();

	static void RegisterSpawnLocations();

protected:
	LegoWorld* m_world;        // 0x154
	IslePathActor* m_unk0x158; // 0x158
	MxFloat m_unk0x15c;        // 0x15c
};

#endif // ISLEPATHACTOR_H
