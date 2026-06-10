#ifndef LEGOANIMATIONMANAGER_H
#define LEGOANIMATIONMANAGER_H

#include "decomp.h"
#include "legolocations.h"
#include "legomain.h"
#include "legostate.h"
#include "legotraninfolist.h"
#include "mxcore.h"
#include "mxgeometry/mxquaternion.h"

class LegoAnimPresenter;
class LegoEntity;
class LegoExtraActor;
class LegoFile;
class LegoPathActor;
class LegoPathBoundary;
class LegoROIList;
struct LegoOrientedEdge;
class LegoWorld;
class MxDSAction;

// SIZE 0x30
struct ModelInfo {
	char* m_name;         // 0x00
	MxU8 m_unk0x04;       // 0x04
	float m_location[3];  // 0x08
	float m_direction[3]; // 0x14
	float m_up[3];        // 0x20
	MxU8 m_unk0x2c;       // 0x2c
};

// SIZE 0x30
struct AnimInfo {
	char* m_name;          // 0x00
	MxU32 m_objectId;      // 0x04
	MxS16 m_location;      // 0x08
	MxBool m_unk0x0a;      // 0x0a
	MxU8 m_unk0x0b;        // 0x0b
	MxU8 m_unk0x0c;        // 0x0c
	MxU8 m_unk0x0d;        // 0x0d
	float m_unk0x10[4];    // 0x10
	MxU8 m_modelCount;     // 0x20
	MxU16 m_unk0x22;       // 0x22
	ModelInfo* m_models;   // 0x24
	MxS8 m_characterIndex; // 0x28
	MxBool m_unk0x29;      // 0x29
	MxS8 m_unk0x2a[3];     // 0x2a
};

// VTABLE: LEGO1 0x100d8d80
// VTABLE: BETA10 0x101bae58
// SIZE 0x1c
class AnimState : public LegoState {
public:
	AnimState();
	~AnimState() override; // vtable+0x00

	// FUNCTION: LEGO1 0x10065070
	// FUNCTION: BETA10 0x1004afe0
	const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f0460
		return "AnimState";
	}

	// FUNCTION: LEGO1 0x10065080
	MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, AnimState::ClassName()) || LegoState::IsA(p_name);
	}

	MxBool Reset() override;                             // vtable+0x18
	MxResult Serialize(LegoStorage* p_storage) override; // vtable+0x1c

	void CopyToAnims(MxU32, AnimInfo* p_anims, MxU32& p_outExtraCharacterId);
	void InitFromAnims(MxU32 p_animsLength, AnimInfo* p_anims, MxU32 p_extraCharacterId);

	// SYNTHETIC: LEGO1 0x10065130
	// AnimState::`scalar deleting destructor'

private:
	MxU32 m_extraCharacterId; // 0x08

	// appears to store the length of m_unk0x10
	MxU32 m_unk0x0c; // 0x0c
	// dynamically sized array of MxU16, corresponding to AnimInfo::m_unk0x22
	MxU16* m_unk0x10; // 0x10

	MxU32 m_locationsFlagsLength; // 0x14
	// dynamically sized array of bools, corresponding to LegoLocation.m_unk0x5c
	MxBool* m_locationsFlags; // 0x18
};

// VTABLE: LEGO1 0x100d8c18
// VTABLE: BETA10 0x101bab60
// SIZE 0x500
class LegoAnimationManager : public MxCore {
public:
	// SIZE 0x18
	struct Character {
		const char* m_name;  // 0x00
		MxBool m_inExtras;   // 0x04
		MxS8 m_vehicleId;    // 0x05
		undefined m_unk0x06; // 0x06 (unused?)
		MxBool m_unk0x07;    // 0x07
		MxBool m_unk0x08;    // 0x08
		MxBool m_unk0x09;    // 0x09
		MxS32 m_unk0x0c;     // 0x0c
		MxS32 m_unk0x10;     // 0x10
		MxBool m_active;     // 0x14
		MxU8 m_unk0x15;      // 0x15
		MxS8 m_unk0x16;      // 0x16
	};

	// SIZE 0x08
	struct Vehicle {
		const char* m_name; // 0x00
		MxBool m_unk0x04;   // 0x04
		MxBool m_unk0x05;   // 0x05
	};

	// SIZE 0x18
	struct Extra {
		LegoROI* m_roi;      // 0x00
		MxS32 m_characterId; // 0x04
		MxLong m_unk0x08;    // 0x08
		MxBool m_unk0x0c;    // 0x0c
		MxBool m_unk0x0d;    // 0x0d
		float m_speed;       // 0x10
		MxBool m_unk0x14;    // 0x14
	};

	enum PlayMode {
		e_unk0 = 0,
		e_unk1,
		e_unk2
	};

	LegoAnimationManager();
	~LegoAnimationManager() override;

	MxLong Notify(MxParam& p_param) override; // vtable+0x04
	MxResult Tickle() override;               // vtable+0x08

	// FUNCTION: LEGO1 0x1005ec80
	// FUNCTION: BETA10 0x100483d0
	const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f7508
		return "LegoAnimationManager";
	}

	// FUNCTION: LEGO1 0x1005ec90
	MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, ClassName()) || MxCore::IsA(p_name);
	}

	void Reset(MxBool p_und);
	void Suspend();
	void Resume();
	void EnableExtras(MxBool p_unk0x400);
	void EnableCamAnims(MxBool p_enableCamAnims);
	MxResult LoadWorldInfo(LegoOmni::World p_worldId);
	MxBool FindVehicle(const char* p_name, MxU32& p_index);
	MxResult ReadAnimInfo(LegoStorage* p_storage, AnimInfo* p_info);
	MxResult ReadModelInfo(LegoStorage* p_storage, ModelInfo* p_info);
	void EnableCharactersByName(const LegoChar* p_characterNames[], MxU32 p_numCharacterNames);
	void SetAllCharactersAnimationEnabled(MxBool p_unk0x08);
	void EnableAnimationsByObjectId(MxS32 p_objectIds[], MxU32 p_numObjectIds);
	void SetAllAnimationsEnabled(MxBool p_unk0x29);
	void SetAutoPlayAnimations(MxBool p_unk0x1a);
	MxResult StartEntityAction(MxDSAction& p_dsAction, LegoEntity* p_entity);
	MxResult StartManagedAnimation(
		MxU32 p_objectId,
		MxMatrix* p_matrix,
		MxBool p_param3,
		MxU8 p_param4,
		LegoROI* p_roi,
		MxBool p_param6,
		MxBool p_param7,
		MxBool p_param8,
		MxBool p_param9
	);
	void CameraTriggerFire(LegoPathActor* p_actor, MxBool, MxU32 p_location, MxBool p_bool);
	void StopAnimations(MxBool p_und);
	LegoTranInfo* GetTranInfo(MxU32 p_index);
	void CacheTransitionSounds();
	void PurgeExtra(MxBool p_und);
	void AddExtra(MxS32 p_location, MxBool p_und);
	void ClaimExtraActorsFromPresenterList(LegoROIList* p_list, LegoAnimPresenter* p_presenter);
	void StashPresenterActors(LegoROIList* p_list);
	MxResult SpawnBricksterAtPoliceStation(Vector3* p_position);
	MxResult SpawnParentsAtHospital(Vector3* p_position);
	MxResult SetExtraActorTiming(const char* p_name, MxS32 p_unk0x0c, MxS32 p_unk0x10);
	MxBool IsAnimationFinished(MxU32 p_objectId);

	static void configureLegoAnimationManager(MxS32 p_legoAnimationManagerConfig);

	// SYNTHETIC: LEGO1 0x1005ed10
	// LegoAnimationManager::`scalar deleting destructor'

private:
	void Init();
	MxResult StartAnimationByIndex(
		MxU32 p_index,
		MxBool p_unk0x0a,
		MxMatrix* p_matrix,
		MxBool p_bool1,
		LegoROI* p_roi,
		MxBool p_bool2,
		MxBool p_bool3,
		MxBool p_bool4,
		MxBool p_bool5
	);
	MxResult StartRawObjectAnimation(MxU32 p_objectId, MxMatrix* p_matrix, MxBool p_und1, MxBool p_und2);
	void DeleteAnimations();
	void StopDeferredAnimations();
	MxResult GetAnimationRangeByLocation(MxS32 p_unk0x08, MxU16& p_unk0x0e, MxU16& p_unk0x10);
	MxU16 FindAmbientAnimationForExtra(
		LegoROI* p_roi,
		Vector3& p_direction,
		Vector3& p_position,
		LegoPathBoundary* p_boundary,
		float p_speed,
		MxU8 p_unk0x0c,
		MxBool p_unk0x14
	);
	MxS8 GetCharacterIndex(const char* p_name);
	MxBool IsAnimationBlockedByVisibleActor(AnimInfo& p_info);
	MxBool ModelExists(AnimInfo& p_info, const char* p_name);
	void DetachActorsUsedByAnimation(AnimInfo& p_info);
	MxBool IsROIWithinSphere(Mx3DPointFloat& p_position, float p_und, LegoROI* p_roi);
	MxBool IsAnimationRejectedForPlayer(AnimInfo& p_info);
	MxBool PromoteROIToExtraActor(LegoROI* p_roi, LegoAnimPresenter* p_presenter);
	void ReleaseStashedActor(LegoROI* p_roi);
	void ReleaseAllStashedActors();
	MxBool BuildExtraActorCycles(LegoWorld* p_world, LegoExtraActor* p_actor, MxU8 p_mood, MxU32 p_characterId);
	void UpdateExtraActorSpeeds();
	void FlushStashedActorsToWorld(LegoAnimPresenter* p_presenter);
	MxBool IsLocationBoundarySpawnable(LegoLocation::Boundary* p_boundary, LegoWorld* p_world);
	MxBool IsEdgeSpawnPointOffscreen(LegoPathBoundary* p_boundary, LegoOrientedEdge* p_edge, float p_destScale);
	MxBool FindRandomSpawnBoundary(LegoLocation::Boundary* p_boundary, MxBool p_bool1, MxBool p_bool2);
	MxResult PlaceNamedExtraActor(
		const char* p_name,
		const char* p_boundaryName,
		MxS32 p_src,
		float p_srcScale,
		MxS32 p_dest,
		float p_destScale,
		MxU32 p_undIdx1,
		MxS32 p_unk0x0c,
		MxU32 p_undIdx2,
		MxS32 p_unk0x10,
		float p_speed
	);
	void BeginAnimationCameraTransition(LegoTranInfo* p_tranInfo, MxLong p_unk0x404);
	void UpdateAnimationCameraTransition(MxLong p_time);

	LegoOmni::World m_worldId;          // 0x08
	MxU16 m_animCount;                  // 0x0c
	MxU16 m_unk0x0e;                    // 0x0e
	MxU16 m_unk0x10;                    // 0x10
	AnimInfo* m_anims;                  // 0x14
	undefined2 m_unk0x18;               // 0x18
	MxBool m_unk0x1a;                   // 0x1a
	MxU32 m_unk0x1c;                    // 0x1c
	LegoTranInfoList* m_tranInfoList;   // 0x20
	LegoTranInfoList* m_tranInfoList2;  // 0x24
	MxPresenter* m_unk0x28[2];          // 0x28
	MxLong m_unk0x30[2];                // 0x30
	MxBool m_unk0x38;                   // 0x38
	MxBool m_animRunning;               // 0x39
	MxBool m_enableCamAnims;            // 0x3a
	Extra m_extras[40];                 // 0x3c
	MxU32 m_lastExtraCharacterId;       // 0x3fc
	MxBool m_unk0x400;                  // 0x400
	MxBool m_unk0x401;                  // 0x401
	MxBool m_unk0x402;                  // 0x402
	MxLong m_unk0x404;                  // 0x404
	MxLong m_unk0x408;                  // 0x408
	MxLong m_unk0x40c;                  // 0x40c
	MxLong m_unk0x410;                  // 0x410
	MxU32 m_unk0x414;                   // 0x414
	MxU32 m_numAllowedExtras;           // 0x418
	MxU32 m_maxAllowedExtras;           // 0x41c
	AnimState* m_animState;             // 0x420
	LegoROIList* m_unk0x424;            // 0x424
	MxBool m_suspendedEnableCamAnims;   // 0x428
	MxBool m_unk0x429;                  // 0x429
	MxBool m_unk0x42a;                  // 0x42a
	MxBool m_suspended;                 // 0x42b
	LegoTranInfo* m_unk0x42c;           // 0x42c
	MxBool m_unk0x430;                  // 0x430
	MxLong m_unk0x434;                  // 0x434
	MxLong m_unk0x438;                  // 0x438
	MxMatrix m_unk0x43c;                // 0x43c
	MxMatrix m_unk0x484;                // 0x484
	MxQuaternionTransformer m_unk0x4cc; // 0x4cc
};

// TEMPLATE: LEGO1 0x10061750
// MxListCursor<LegoTranInfo *>::MxListCursor<LegoTranInfo *>

// TEMPLATE: BETA10 0x1004b5d0
// MxListCursor<LegoTranInfo *>::Next

#endif // LEGOANIMATIONMANAGER_H
