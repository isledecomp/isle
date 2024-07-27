#ifndef LEGORACERS_H
#define LEGORACERS_H

#include "legocarraceactor.h"
#include "legoracemap.h"

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
	) override;                                                          // vtable+0x6c
	void VTable0x70(float p_float) override;                             // vtable+0x70
	MxResult VTable0x94(LegoPathActor* p_actor, MxBool p_bool) override; // vtable+0x94
	void SwitchBoundary(LegoPathBoundary*& p_boundary, LegoUnknown100db7f4*& p_edge, float& p_unk0xe4)
		override;                   // vtable+0x98
	MxResult VTable0x9c() override; // vtable+0x9c

	virtual void SetMaxLinearVelocity(float p_maxLinearVelocity);
	virtual void FUN_10012ff0(float p_param);
	virtual MxU32 HandleSkeletonKicks(float p_param1);

	// SYNTHETIC: LEGO1 0x10014240
	// LegoRaceCar::`scalar deleting destructor'

private:
	undefined m_userState;          // 0x54
	float m_unk0x58;                // 0x58
	Mx3DPointFloat m_unk0x5c;       // 0x5c
	LegoAnimActorStruct* m_unk0x70; // 0x70
	LegoAnimActorStruct* m_unk0x74; // 0x74
	LegoPathBoundary* m_unk0x78;    // 0x78
	LegoPathBoundary* m_unk0x7c;    // 0x7c

	static EdgeReference g_skBMap[]; // name verified by BETA10 0x100cbee6
	static const SkeletonKickPhase g_skeletonKickPhases[];
	static const char* g_strSpeed;
	static const char* g_srtsl18to29[];
	static const char* g_srtsl6to10[];
	static const char* g_emptySoundKeyList[];
	static const char* g_srtrh[];
	static const char* g_srt001ra;
	static const char* g_soundSkel3;
	static MxU32 g_srtsl18to29Index;
	static MxU32 g_srtsl6to10Index;
	static MxU32 g_emptySoundKeyListIndex;
	static MxU32 g_srtrhIndex;
	static MxLong g_timeLastSoundPlayed;
	static MxS32 g_unk0x100f0b88;
	static MxBool g_unk0x100f0b8c;
	static Mx3DPointFloat g_unk0x10102af0;
};

#endif // LEGORACERS_H
