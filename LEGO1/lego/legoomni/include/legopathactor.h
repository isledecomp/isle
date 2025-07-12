#ifndef LEGOPATHACTOR_H
#define LEGOPATHACTOR_H

#include "legoactor.h"
#include "misc/legospline.h"
#include "mxtypes.h"

struct LegoEdge;
struct LegoNamedPlane;
class LegoPathBoundary;
class LegoPathController;
struct LegoPathEdgeContainer;
struct LegoOrientedEdge;
class LegoWEEdge;

extern MxLong g_timeLastHitSoundPlayed;
extern const char* g_strHIT_WALL_SOUND;

// VTABLE: LEGO1 0x100d6e28
// VTABLE: BETA10 0x101bdc08
// SIZE 0x154
class LegoPathActor : public LegoActor {
public:
	enum ActorState {
		// States
		c_initial = 0,
		c_ready = 1,
		c_hit = 2,
		c_hitAnimation = 3,
		c_disabled = 4,
		c_maxState = 255,

		// Flags
		c_noCollide = 0x100
	};

	LegoPathActor();
	~LegoPathActor() override;

	void ParseAction(char* p_extra) override; // vtable+0x20
	virtual MxS32 CheckIntersections(
		Vector3& p_rayOrigin,
		Vector3& p_rayEnd,
		Vector3& p_intersectionPoint
	); // vtable+0x68
	virtual MxU32 CheckPresenterAndActorIntersections(
		LegoPathBoundary* p_boundary,
		Vector3& p_rayOrigin,
		Vector3& p_rayDirection,
		float p_rayLength,
		float p_radius,
		Vector3& p_intersectionPoint
	);                                                 // vtable+0x6c
	virtual void Animate(float p_time);                // vtable+0x70
	virtual void ApplyTransform(Matrix4& p_transform); // vtable+0x74

	// FUNCTION: LEGO1 0x10002d20
	// FUNCTION: BETA10 0x1000f500
	virtual void SetUserNavFlag(MxBool p_userNavFlag) { m_userNavFlag = p_userNavFlag; } // vtable+0x78

	// FUNCTION: LEGO1 0x10002d30
	// FUNCTION: BETA10 0x1000f530
	virtual MxBool GetUserNavFlag() { return m_userNavFlag; } // vtable+0x7c

	virtual MxResult SetSpline(
		const Vector3& p_start,
		Vector3& p_tangentAtStart,
		Vector3& p_end,
		Vector3& p_tangentAtEnd
	); // vtable+0x80
	virtual MxResult SetTransformAndDestinationFromPoints(
		LegoPathBoundary* p_boundary,
		float p_time,
		Vector3& p_start,
		Vector3& p_direction,
		LegoOrientedEdge* p_destEdge,
		float p_destScale
	); // vtable+0x84
	virtual MxResult SetTransformAndDestinationFromEdge(
		LegoPathBoundary* p_boundary,
		float p_time,
		LegoEdge& p_srcEdge,
		float p_srcScale,
		LegoOrientedEdge& p_destEdge,
		float p_destScale
	);                                                                    // vtable+0x88
	virtual MxS32 CalculateTransform(float p_time, Matrix4& p_transform); // vtable+0x8c

	// FUNCTION: LEGO1 0x10002d40
	// FUNCTION: BETA10 0x1000f560
	virtual MxU32 StepState(float, Matrix4&) { return FALSE; } // vtable+0x90

	// FUNCTION: LEGO1 0x10002d50
	// FUNCTION: BETA10 0x1000f800
	virtual MxResult HitActor(LegoPathActor*, MxBool) { return 0; } // vtable+0x94

	virtual void SwitchBoundary(
		LegoPathBoundary*& p_boundary,
		LegoOrientedEdge*& p_edge,
		float& p_scale
	);                                  // vtable+0x98
	virtual MxResult CalculateSpline(); // vtable+0x9c

	// FUNCTION: LEGO1 0x10002d60
	// FUNCTION: BETA10 0x1000f820
	virtual MxS32 NextTargetLocation() { return 0; } // vtable+0xa0

	virtual void GetWalkingBehavior(MxBool& p_countCounterclockWise, MxS32& p_selectedEdgeIndex); // vtable+0xa4
	virtual void ApplyLocal2World();                                                              // vtable+0xa8

	// FUNCTION: LEGO1 0x10002d70
	// FUNCTION: BETA10 0x1000f580
	virtual void SetMaxLinearVel(MxFloat p_maxLinearVel) { m_maxLinearVel = p_maxLinearVel; } // vtable+0xac

	// FUNCTION: LEGO1 0x10002d80
	// FUNCTION: BETA10 0x1000f5b0
	virtual MxFloat GetMaxLinearVel() { return m_maxLinearVel; } // vtable+0xb0

	// FUNCTION: LEGO1 0x10002d90
	// FUNCTION: BETA10 0x1000f5e0
	virtual MxFloat GetWallHitDirectionFactor() { return m_wallHitDirectionFactor; } // vtable+0xb4

	// FUNCTION: LEGO1 0x10002da0
	// FUNCTION: BETA10 0x1000f610
	virtual MxFloat GetWallHitDampening() { return m_wallHitDampening; } // vtable+0xb8

	// FUNCTION: LEGO1 0x10002db0
	// FUNCTION: BETA10 0x1000f640
	virtual void SetWallHitDirectionFactor(MxFloat p_wallHitDirectionFactor)
	{
		m_wallHitDirectionFactor = p_wallHitDirectionFactor;
	} // vtable+0xbc

	// FUNCTION: LEGO1 0x10002dc0
	// FUNCTION: BETA10 0x1000f670
	virtual void SetWallHitDampening(MxFloat p_wallHitDampening)
	{
		m_wallHitDampening = p_wallHitDampening;
	} // vtable+0xc0

	// FUNCTION: LEGO1 0x10002dd0
	// FUNCTION: BETA10 0x1000f6a0
	virtual void VTable0xc4() {} // vtable+0xc4

	// FUNCTION: LEGO1 0x10002de0
	virtual void SetCanRotate(MxU8 p_canRotate) { m_canRotate = p_canRotate; } // vtable+0xc8

	// FUNCTION: LEGO1 0x1000c430
	// FUNCTION: BETA10 0x10012790
	const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f0114
		return "LegoPathActor";
	}

	// FUNCTION: LEGO1 0x1000c440
	// FUNCTION: BETA10 0x100124c0
	MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, LegoPathActor::ClassName()) || LegoActor::IsA(p_name);
	}

	// FUNCTION: BETA10 0x1001ca40
	LegoPathBoundary* GetBoundary() { return m_boundary; }

	// FUNCTION: BETA10 0x1001c860
	MxU32 GetActorState() { return m_actorState; }

	LegoPathController* GetController() { return m_pathController; }
	MxBool GetCollideBox() { return m_collideBox; }
	MxFloat GetTransformTime() { return m_transformTime; }
	MxFloat GetActorTime() { return m_actorTime; }

	void SetBoundary(LegoPathBoundary* p_boundary) { m_boundary = p_boundary; }

	// FUNCTION: BETA10 0x10013430
	void SetActorState(MxU32 p_actorState) { m_actorState = p_actorState; }

	void SetController(LegoPathController* p_pathController) { m_pathController = p_pathController; }
	void SetTransformTime(MxFloat p_transformTime) { m_transformTime = p_transformTime; }
	void SetActorTime(MxFloat p_actorTime) { m_actorTime = p_actorTime; }

	void UpdatePlane(LegoNamedPlane& p_namedPlane);
	void PlaceActor(LegoNamedPlane& p_namedPlane);

	// SYNTHETIC: LEGO1 0x1002d800
	// SYNTHETIC: BETA10 0x100b04d0
	// LegoPathActor::`scalar deleting destructor'

protected:
	inline MxU32 CheckIntersectionBothFaces(
		list<LegoPathBoundary*>& p_checkedBoundaries,
		LegoPathBoundary* p_boundary,
		Vector3& p_rayOrigin,
		Vector3& p_rayDirection,
		float p_rayLength,
		float p_radius,
		Vector3& p_intersectionPoint,
		MxS32 p_depth
	);

	MxFloat m_BADuration;                 // 0x78
	MxFloat m_traveledDistance;           // 0x7c
	MxFloat m_actorTime;                  // 0x80
	MxFloat m_transformTime;              // 0x84
	LegoPathBoundary* m_boundary;         // 0x88
	LegoSpline m_spline;                  // 0x8c
	MxU32 m_actorState;                   // 0xdc
	LegoOrientedEdge* m_destEdge;         // 0xe0
	MxFloat m_destScale;                  // 0xe4
	MxBool m_collideBox;                  // 0xe8
	MxBool m_finishedTravel;              // 0xe9
	MxBool m_userNavFlag;                 // 0xea
	MxMatrix m_local2World;               // 0xec
	LegoPathEdgeContainer* m_grec;        // 0x134
	LegoPathController* m_pathController; // 0x138
	MxFloat m_maxLinearVel;               // 0x13c
	MxFloat m_wallHitDirectionFactor;     // 0x140
	MxFloat m_wallHitDampening;           // 0x144
	MxU8 m_canRotate;                     // 0x148
	MxS32 m_lastRotationAngle;            // 0x14c
	MxFloat m_linearRotationRatio;        // 0x150
};

// FUNCTION: LEGO1 0x1002edd0
// LegoPathActor::CheckIntersectionBothFaces

// TEMPLATE: LEGO1 0x10018b70
// List<LegoBoundaryEdge>::~List<LegoBoundaryEdge>

// TEMPLATE: LEGO1 0x10018bc0
// list<LegoBoundaryEdge,allocator<LegoBoundaryEdge> >::~list<LegoBoundaryEdge,allocator<LegoBoundaryEdge> >

// TEMPLATE: LEGO1 0x1002ef10
// list<LegoPathBoundary *,allocator<LegoPathBoundary *> >::~list<LegoPathBoundary *,allocator<LegoPathBoundary *> >

// TEMPLATE: LEGO1 0x1002ef80
// list<LegoPathBoundary *,allocator<LegoPathBoundary *> >::insert

// TEMPLATE: LEGO1 0x1002efd0
// List<LegoPathBoundary *>::~List<LegoPathBoundary *>

#endif // LEGOPATHACTOR_H
