#ifndef ACT3ACTORS_H
#define ACT3ACTORS_H

#include "legoanimactor.h"

// File name verified by multiple assertions, e.g. BETA10 0x10018391

class Act3Ammo;
class LegoWorld;

// VTABLE: LEGO1 0x100d7668 LegoPathActor
// VTABLE: LEGO1 0x100d7738 LegoAnimActor
// VTABLE: BETA10 0x101b8a98 LegoPathActor
// SIZE 0x178
class Act3Actor : public LegoAnimActor {
public:
	struct Act3CopDest {
		// name verified by BETA10 0x10018776
		const char* m_bName; // 0x00

		// name verified by BETA10 0x100187cb
		LegoPathBoundary* m_boundary; // 0x04

		MxFloat m_unk0x08[3]; // 0x08
		MxFloat m_unk0x14[3]; // 0x14
	};

	Act3Actor();

	// FUNCTION: LEGO1 0x100431b0
	const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f03ac
		return "Act3Actor";
	}

	MxU32 VTable0x90(float p_time, Matrix4& p_transform) override;     // vtable+0x90
	MxResult HitActor(LegoPathActor* p_actor, MxBool p_bool) override; // vtable+0x94

	MxFloat GetUnknown0x1c() { return m_unk0x1c; }

	void SetUnknown0x1c(MxFloat p_unk0x1c) { m_unk0x1c = p_unk0x1c; }

	// SYNTHETIC: LEGO1 0x10043330
	// Act3Actor::`scalar deleting destructor'

	// SYNTHETIC: LEGO1 0x10040fa0
	// Act3Actor::~Act3Actor

private:
	static Mx3DPointFloat g_unk0x10104ef0;

	MxFloat m_unk0x1c; // 0x1c
};

// VTABLE: LEGO1 0x100d7750 LegoPathActor
// VTABLE: LEGO1 0x100d7820 LegoAnimActor
// SIZE 0x188
class Act3Cop : public Act3Actor {
public:
	Act3Cop();

	void ParseAction(char* p_extra) override;           // vtable+0x20
	void Animate(float p_time) override;                // vtable+0x70
	MxResult HitActor(LegoPathActor*, MxBool) override; // vtable+0x94
	MxResult VTable0x9c() override;                     // vtable+0x9c

	MxFloat GetUnknown0x20() { return m_unk0x20; }

	void SetUnknown0x20(MxFloat p_unk0x20) { m_unk0x20 = p_unk0x20; }

	MxResult FUN_10040350(Act3Ammo& p_ammo, const Vector3&);
	MxResult FUN_10040360();

	// SYNTHETIC: LEGO1 0x10043120
	// Act3Cop::`scalar deleting destructor'

private:
	MxFloat m_unk0x20;  // 0x20
	LegoWorld* m_world; // 0x24

	// name verified by BETA10 0x10018aa1
	LegoAnimActorStruct* m_eatAnim; // 0x28

	undefined4 m_unk0x2c; // 0x2c
};

// VTABLE: LEGO1 0x100d7838 LegoPathActor
// VTABLE: LEGO1 0x100d7908 LegoAnimActor
// SIZE 0x1b4
class Act3Brickster : public Act3Actor {
public:
	Act3Brickster();
	~Act3Brickster() override;

	void ParseAction(char* p_extra) override;                          // vtable+0x20
	void Animate(float p_time) override;                               // vtable+0x70
	MxResult HitActor(LegoPathActor* p_actor, MxBool p_bool) override; // vtable+0x94
	void SwitchBoundary(
		LegoPathBoundary*& p_boundary,
		LegoUnknown100db7f4*& p_edge,
		float& p_unk0xe4
	) override;                     // vtable+0x98
	MxResult VTable0x9c() override; // vtable+0x9c

	MxFloat GetUnknown0x20() { return m_unk0x20; }
	MxFloat GetUnknown0x24() { return m_unk0x24; }
	MxFloat GetUnknown0x50() { return m_unk0x50; }

	void SetUnknown0x20(MxFloat p_unk0x20) { m_unk0x20 = p_unk0x20; }
	void SetUnknown0x24(MxFloat p_unk0x24) { m_unk0x24 = p_unk0x24; }
	void SetUnknown0x50(MxFloat p_unk0x50) { m_unk0x50 = p_unk0x50; }

	MxResult FUN_100417a0(Act3Ammo& p_ammo, const Vector3&);
	MxResult FUN_100417c0();

	// SYNTHETIC: LEGO1 0x10043250
	// Act3Brickster::`scalar deleting destructor'

private:
	MxFloat m_unk0x20;                // 0x20
	MxFloat m_unk0x24;                // 0x24
	LegoWorld* m_world;               // 0x28
	undefined4 m_unk0x2c;             // 0x2c
	undefined4 m_unk0x30;             // 0x30
	LegoAnimActorStruct* m_shootAnim; // 0x34
	undefined4 m_unk0x38;             // 0x38
	Mx3DPointFloat m_unk0x3c;         // 0x3c
	MxFloat m_unk0x50;                // 0x50
	undefined4 m_unk0x54;             // 0x54
	undefined m_unk0x58;              // 0x58
};

// VTABLE: LEGO1 0x100d7920 LegoPathActor
// VTABLE: LEGO1 0x100d79f0 LegoAnimActor
// SIZE 0x1a8
class Act3Shark : public LegoAnimActor {
public:
	Act3Shark();

	// FUNCTION: LEGO1 0x100430d0
	const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f03a0
		return "Act3Shark";
	}

	void ParseAction(char*) override;    // vtable+0x20
	void Animate(float p_time) override; // vtable+0x70

	// LegoAnimActor vtable
	virtual MxResult FUN_10042ce0(Act3Ammo* p_ammo); // vtable+0x10

	MxFloat GetUnknown0x2c() { return m_unk0x2c; }

	void SetUnknown0x2c(MxFloat p_unk0x2c) { m_unk0x2c = p_unk0x2c; }

	// SYNTHETIC: LEGO1 0x10043030
	// Act3Shark::`scalar deleting destructor'

private:
	list<Act3Ammo*> m_unk0x1c;      // 0x1c
	Act3Ammo* m_unk0x28;            // 0x28
	MxFloat m_unk0x2c;              // 0x2c
	LegoWorld* m_world;             // 0x30
	LegoAnimActorStruct* m_unk0x34; // 0x34
	LegoROI* m_unk0x38;             // 0x38
	Mx3DPointFloat m_unk0x3c;       // 0x3c
};

// FUNCTION: LEGO1 0x1003ff10
// Act3Actor::`vbase destructor'

// TEMPLATE: LEGO1 0x10042c20
// list<Act3Ammo *,allocator<Act3Ammo *> >::~list<Act3Ammo *,allocator<Act3Ammo *> >

// TEMPLATE: LEGO1 0x10042c90
// List<Act3Ammo *>::~List<Act3Ammo *>

// TEMPLATE: LEGO1 0x10042ee0
// list<Act3Ammo *,allocator<Act3Ammo *> >::erase

// GLOBAL: LEGO1 0x100d7660
// Act3Actor::`vbtable'

// GLOBAL: LEGO1 0x100d7748
// Act3Cop::`vbtable'

// GLOBAL: LEGO1 0x100d7830
// Act3Brickster::`vbtable'

// GLOBAL: LEGO1 0x100d7918
// Act3Shark::`vbtable'

#endif // ACT3ACTORS_H
