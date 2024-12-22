#ifndef LEGORACERS_H
#define LEGORACERS_H

#include "legojetskiraceactor.h"
#include "legoracemap.h"
#include "legoracespecial.h"

#define LEGORACECAR_UNKNOWN_0 0
#define LEGORACECAR_UNKNOWN_1 1
#define LEGORACECAR_KICK1 2 // name guessed
#define LEGORACECAR_KICK2 4 // name validated by BETA10 0x100cb659

// SIZE 0x08
struct EdgeReference {
	const char* m_name; // 0x00
	// name verified by BETA10 0x100cbee6
	LegoPathBoundary* m_b; // 0x04
};

// SIZE 0x10
struct SkeletonKickPhase {
	EdgeReference* m_edgeRef; // 0x00
	float m_lower;            // 0x04
	float m_upper;            // 0x08
	MxU8 m_userState;         // 0x0c
};

// VTABLE: LEGO1 0x100d58a0 LegoRaceActor
// VTABLE: LEGO1 0x100d58a8 LegoAnimActor
// VTABLE: LEGO1 0x100d58b8 LegoPathActor
// VTABLE: LEGO1 0x100d5984 LegoRaceMap
// VTABLE: LEGO1 0x100d5988 LegoCarRaceActor
// VTABLE: BETA10 0x101be6ec LegoRaceActor
// VTABLE: BETA10 0x101be6f0 LegoAnimActor
// VTABLE: BETA10 0x101be708 LegoPathActor
// VTABLE: BETA10 0x101be7f8 LegoRaceMap
// VTABLE: BETA10 0x101be800 LegoCarRaceActor
// SIZE 0x200
class LegoRaceCar : public LegoCarRaceActor, public LegoRaceMap {
public:
	LegoRaceCar();
	~LegoRaceCar() override;

	MxLong Notify(MxParam& p_param) override; // vtable+0x04

	// FUNCTION: LEGO1 0x100142a0
	// FUNCTION: BETA10 0x100cd500
	const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f0548
		return "LegoRaceCar";
	}

	// FUNCTION: LEGO1 0x100142c0
	MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, LegoRaceCar::ClassName()) || LegoCarRaceActor::IsA(p_name);
	}

	void ParseAction(char* p_extra) override;          // vtable+0x20
	void SetWorldSpeed(MxFloat p_worldSpeed) override; // vtable+0x30
	MxU32 VTable0x6c(
		LegoPathBoundary* p_boundary,
		Vector3& p_v1,
		Vector3& p_v2,
		float p_f1,
		float p_f2,
		Vector3& p_v3
	) override;                                                        // vtable+0x6c
	void Animate(float p_time) override;                               // vtable+0x70
	MxResult HitActor(LegoPathActor* p_actor, MxBool p_bool) override; // vtable+0x94
	void SwitchBoundary(LegoPathBoundary*& p_boundary, LegoUnknown100db7f4*& p_edge, float& p_unk0xe4)
		override;                   // vtable+0x98
	MxResult VTable0x9c() override; // vtable+0x9c

	virtual void SetMaxLinearVelocity(float p_maxLinearVelocity);
	virtual void FUN_10012ff0(float p_param);
	virtual MxU32 HandleSkeletonKicks(float p_param1);

	static void FUN_10012de0();
	static void FUN_10012e00();
	static void FUN_10013670();

	// SYNTHETIC: LEGO1 0x10014240
	// LegoRaceCar::`scalar deleting destructor'

private:
	undefined m_userState;    // 0x54
	float m_unk0x58;          // 0x58
	Mx3DPointFloat m_unk0x5c; // 0x5c

	// Names verified by BETA10 0x100cb4a9
	LegoAnimActorStruct* m_skelKick1Anim; // 0x70
	LegoAnimActorStruct* m_skelKick2Anim; // 0x74

	// Name verified by BETA10 0x100cb4f0
	LegoPathBoundary* m_kick1B; // 0x78

	// Name verified by BETA10 0x100cb537
	LegoPathBoundary* m_kick2B; // 0x7c
};

// VTABLE: LEGO1 0x100d5a08 LegoCarRaceActor
// VTABLE: LEGO1 0x100d5a28 LegoRaceActor
// VTABLE: LEGO1 0x100d5a30 LegoAnimActor
// VTABLE: LEGO1 0x100d5a40 LegoPathActor
// VTABLE: LEGO1 0x100d5b10 LegoRaceMap
// VTABLE: BETA10 0x101be8a0 LegoCarRaceActor
// VTABLE: BETA10 0x101be8c8 LegoRaceActor
// VTABLE: BETA10 0x101be8d0 LegoAnimActor
// VTABLE: BETA10 0x101be8e8 LegoPathActor
// VTABLE: BETA10 0x101be9d8 LegoRaceMap
// SIZE 0x1dc
class LegoJetski : public LegoJetskiRaceActor, public LegoRaceMap {
public:
	LegoJetski();
	~LegoJetski() override;

	MxLong Notify(MxParam& p_param) override; // vtable+0x04

	// FUNCTION: LEGO1 0x10013e90
	// FUNCTION: BETA10 0x100cd1f0
	const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f053c
		return "LegoJetski";
	}

	// FUNCTION: LEGO1 0x10013eb0
	MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, LegoJetski::ClassName()) || LegoJetskiRaceActor::IsA(p_name);
	}

	void ParseAction(char* p_extra) override;          // vtable+0x20
	void SetWorldSpeed(MxFloat p_worldSpeed) override; // vtable+0x30
	MxU32 VTable0x6c(
		LegoPathBoundary* p_boundary,
		Vector3& p_v1,
		Vector3& p_v2,
		float p_f1,
		float p_f2,
		Vector3& p_v3
	) override;                                                        // vtable+0x6c
	void Animate(float p_time) override;                               // vtable+0x70
	MxResult HitActor(LegoPathActor* p_actor, MxBool p_bool) override; // vtable+0x94
	void SwitchBoundary(LegoPathBoundary*& p_boundary, LegoUnknown100db7f4*& p_edge, float& p_unk0xe4)
		override;                   // vtable+0x98
	MxResult VTable0x9c() override; // vtable+0x9c

	virtual void FUN_100136f0(float p_worldSpeed);

	// SYNTHETIC: LEGO1 0x10013e30
	// LegoJetski::`scalar deleting destructor'
};

// GLOBAL: LEGO1 0x100d5890
// LegoRaceCar::`vbtable'{for `LegoCarRaceActor'}

// GLOBAL: LEGO1 0x100d5880
// LegoRaceCar::`vbtable'{for `LegoRaceMap'}

// GLOBAL: LEGO1 0x100d5878
// LegoRaceCar::`vbtable'{for `LegoAnimActor'}

// GLOBAL: LEGO1 0x100d5868
// LegoRaceCar::`vbtable'{for `LegoRaceActor'}

// GLOBAL: LEGO1 0x100d59b8
// LegoJetski::`vbtable'{for `LegoCarRaceActor'}

// GLOBAL: LEGO1 0x100d59c8
// LegoJetski::`vbtable'{for `LegoRaceActor'}

// GLOBAL: LEGO1 0x100d59d8
// LegoJetski::`vbtable'{for `LegoAnimActor'}

// GLOBAL: LEGO1 0x100d59e0
// LegoJetski::`vbtable'

// GLOBAL: LEGO1 0x100d59f0
// LegoJetski::`vbtable'{for `LegoJetskiRaceActor'}

#endif // LEGORACERS_H
