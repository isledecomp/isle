#ifndef ACT2ACTOR_H
#define ACT2ACTOR_H

#include "legoanimactor.h"

// VTABLE: LEGO1 0x100d6078 LegoPathActor
// VTABLE: LEGO1 0x100d6148 LegoAnimActor
// VTABLE: BETA10 0x101b80c0 LegoPathActor
// VTABLE: BETA10 0x101b81b0 LegoAnimActor
// SIZE 0x1a8
class Act2Actor : public LegoAnimActor {
public:
	struct Location {
		MxFloat m_position[3];  // 0x00
		MxFloat m_direction[3]; // 0x0c
		const char* m_boundary; // 0x18
		MxBool m_cleared;       // 0x1c
	};

	enum VoiceOver {
		e_head = 0,
		e_behind = 1,
		e_interrupt = 2,
	};

	Act2Actor();

	void SetROI(LegoROI* p_roi, MxBool p_bool1, MxBool p_updateTransform) override; // vtable+0x24
	void SetWorldSpeed(MxFloat p_worldSpeed) override;                              // vtable+0x30

	// FUNCTION: LEGO1 0x1001a180
	MxS32 CheckIntersections(Vector3& p_v1, Vector3& p_v2, Vector3& p_v3) override
	{
		if (m_animatingHit) {
			return 0;
		}

		return LegoAnimActor::CheckIntersections(p_v1, p_v2, p_v3);
	} // vtable+0x68

	void Animate(float p_time) override;                // vtable+0x70
	MxResult HitActor(LegoPathActor*, MxBool) override; // vtable+0x94
	MxResult CalculateSpline() override;                // vtable+0x9c
	MxS32 NextTargetLocation() override;                // vtable+0xa0

	void InitializeNextShot();
	void SetWorldSpeed(MxFloat p_speed, MxFloat p_resetWorldSpeedAt);
	void GoingToHide();
	void Hide();
	MxU32 UpdateShot(MxFloat p_time);
	void PlayNextVoiceOver(MxS8 p_voiceOverType);
	void FindPath(MxU32 p_location);
	LegoEntity* GetNextEntity(MxBool* p_isBuilding);

	// SYNTHETIC: LEGO1 0x1001a0a0
	// Act2Actor::`scalar deleting destructor'

	// GLOBAL: LEGO1 0x100d6070
	// GLOBAL: BETA10 0x101b80b0
	// `vbtable'

private:
	enum {
		e_readyToShoot = 0,
		e_endShot = 1,
		e_roaming = 2,
		e_createdBrick = 3,
		e_goingToHide = 4,
		e_hiding = 5,
	};

	MxBool m_skipAnimation;             // 0x1c
	MxS8 m_targetLocation;              // 0x1d
	MxU8 m_state;                       // 0x1e
	MxBool m_animatingHit;              // 0x1f
	MxFloat m_animationDuration;        // 0x20
	MxFloat m_createBrickTime;          // 0x24
	MxS8 m_baseWorldSpeed;              // 0x28
	MxFloat m_shootAnimEnd;             // 0x2c
	MxFloat m_entityAnimationTime;      // 0x30
	LegoAnimActorStruct* m_shootAnim;   // 0x34
	LegoCacheSound* m_cachedShootSound; // 0x38
	undefined4 m_unk0x3c;               // 0x3c
	MxBool m_initializing;              // 0x40
	MxFloat m_resetWorldSpeedAt;        // 0x44
	MxS8 m_visitedLocations;            // 0x48
	LegoEntity* m_nextEntity;           // 0x4c
};

// TEMPLATE: LEGO1 0x100194f0
// list<LegoBoundaryEdge,allocator<LegoBoundaryEdge> >::list<LegoBoundaryEdge,allocator<LegoBoundaryEdge> >

#endif // ACT2ACTOR_H
