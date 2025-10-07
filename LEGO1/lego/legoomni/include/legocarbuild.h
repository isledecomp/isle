#ifndef LEGOCARBUILD_H
#define LEGOCARBUILD_H

#include "legogamestate.h"
#include "legostate.h"
#include "legoworld.h"
#include "mxgeometry/mxquaternion.h"

class LegoCarBuildAnimPresenter;
class LegoControlManagerNotificationParam;
class LegoEventNotificationParam;
class MxControlPresenter;
class MxStillPresenter;
class MxSoundPresenter;
class MxActionNotificationParam;

// VTABLE: LEGO1 0x100d66e0
// VTABLE: BETA10 0x101bb910
// SIZE 0x50
class LegoVehicleBuildState : public LegoState {
public:
	enum AnimationState {
		e_none = 0,
		e_entering = 1,
		e_settingUpMovie = 2,
		e_cutscene = 3,
		e_finishedBuild = 4,
		e_exiting = 6
	};

	LegoVehicleBuildState(const char* p_classType);

	// FUNCTION: LEGO1 0x10025ff0
	const char* ClassName() const override // vtable+0x0c
	{
		return m_className.GetData();
	}

	// FUNCTION: LEGO1 0x10026000
	MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, m_className.GetData()) || LegoState::IsA(p_name);
	}

	MxResult Serialize(LegoStorage* p_storage) override; // vtable+0x1c

	// SYNTHETIC: LEGO1 0x100260a0
	// LegoVehicleBuildState::`scalar deleting destructor'

	Playlist m_unk0x08[4]; // 0x08

	// This can be one of the following:
	// * LegoRaceCarBuildState
	// * LegoCopterBuildState
	// * LegoDuneCarBuildState
	// * LegoJetskiBuildState
	MxString m_className; // 0x38

	AnimationState m_animationState; // 0x48
	MxU8 m_introductionCounter;      // 0x4c
	MxBool m_finishedBuild;          // 0x4d
	MxBool m_playedExitScript;       // 0x4e
	MxU8 m_placedPartCount;          // 0x4f
};

typedef LegoVehicleBuildState LegoRaceCarBuildState;
typedef LegoVehicleBuildState LegoCopterBuildState;
typedef LegoVehicleBuildState LegoDuneCarBuildState;
typedef LegoVehicleBuildState LegoJetskiBuildState;

// VTABLE: LEGO1 0x100d6658
// VTABLE: BETA10 0x101bb880
// SIZE 0x34c
class LegoCarBuild : public LegoWorld {
public:
	// SIZE 0x1c
	struct LookupTableActions {
		MxU32 m_introduction0;    // 0x00
		MxU32 m_leaveUnfinished;  // 0x04
		MxU32 m_completed;        // 0x08
		MxU32 m_introduction1;    // 0x0c
		MxU32 m_introduction2;    // 0x10
		MxU32 m_introduction3;    // 0x14
		MxU32 m_shortExplanation; // 0x18
	};

	enum LookupTableActionType {
		e_introduction0 = 0,
		e_introduction1 = 1,
		e_introduction2 = 2,
		e_introduction3 = 3,
		e_leaveUnfinished = 4,
		e_completed = 5,
		e_shortExplanation = 6,
	};

	enum ResetPlacedSelectedPart {
		c_disabled = -1,
		c_enabled = 8
	};

	LegoCarBuild();
	~LegoCarBuild() override;

	// FUNCTION: LEGO1 0x10022930
	// FUNCTION: BETA10 0x10070070
	MxBool WaitForTransition() override { return TRUE; } // vtable+0x5c

	// FUNCTION: LEGO1 0x10022940
	// FUNCTION: BETA10 0x10070090
	const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f0504
		return "LegoCarBuild";
	}

	MxLong Notify(MxParam& p_param) override; // vtable+0x04
	MxResult Tickle() override;               // vtable+0x08

	// FUNCTION: LEGO1 0x10022950
	MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, LegoCarBuild::ClassName()) || LegoWorld::IsA(p_name);
	}

	MxResult Create(MxDSAction& p_dsAction) override;                                            // vtable+0x18
	void ReadyWorld() override;                                                                  // vtable+0x50
	MxBool Escape() override;                                                                    // vtable+0x64
	void Enable(MxBool p_enable) override;                                                       // vtable+0x68
	virtual void InitializeDisplayingTransform();                                                // vtable+0x6c
	virtual void CalculateStartAndTargetScreenPositions();                                       // vtable+0x70
	virtual void CalculateDragPositionAbove(MxFloat p_coordinates[2], MxFloat p_position[3]);    // vtable+0x74
	virtual void CalculateDragPositionBetween(MxFloat p_coordinates[2], MxFloat p_position[3]);  // vtable+0x78
	virtual void CalculateDragPositionOnGround(MxFloat p_coordinates[2], MxFloat p_position[3]); // vtable+0x7c
	virtual void VTable0x80(
		MxFloat p_param1[2],
		MxFloat p_param2[2],
		MxFloat p_param3,
		MxFloat p_param4[2]
	); // vtable+0x80

	MxS16 GetPlacedPartCount();
	void SetPlacedPartCount(MxU8 p_placedPartCount);
	void InitPresenters();
	void DisplaySelectedPart();
	void ResetSelectedPart();
	void CalculateSelectedPartMatrix(MxLong p_x, MxLong p_y);
	void AddSelectedPartToBuild();
	MxLong HandleKeyPress(LegoEventNotificationParam* p_param);
	void InitExiting();
	MxLong HandleEndAction(MxActionNotificationParam* p_param);
	MxLong SelectPartFromMousePosition(MxLong p_x, MxLong p_y);
	MxLong HandleButtonUp(MxLong p_x, MxLong p_y);
	MxLong HandleMouseMove(MxLong p_x, MxLong p_y);
	MxLong HandleControl(MxParam* p_param);
	MxLong HandleType0Notification(MxNotificationParam* p_param);
	void StartIntroduction();
	void MoveShelves();
	void RotateVehicle();
	void EnableColorControlsForSelectedPart(MxBool p_enabled);
	void SetColorControlsEnabled(MxBool p_enabled);
	void ToggleColorControlsEnabled();
	void EnableDecalForSelectedPart(MxBool p_enabled);
	void SetPartColor(MxS32 p_objectId);
	void CalculateStartAndTargetTransforms();
	void StartActorScriptByType(MxS32 p_actionType);
	void StartActorScript(MxS32 p_streamId);
	MxS32 GetNextIntroduction();
	void TickleControl(const char* p_controlName, MxULong p_time);
	void HandleEndAnim();
	MxS32 GetBuildMovieId(MxS32 p_carId);

	// FUNCTION: BETA10 0x100735b0
	void SetCarBuildAnimPresenter(LegoCarBuildAnimPresenter* p_animPresenter) { m_animPresenter = p_animPresenter; }

	// SYNTHETIC: LEGO1 0x10022a60
	// LegoCarBuild::`scalar deleting destructor'

private:
	enum {
		e_idle = 0,
		e_returning = 3,
		e_selecting = 4,
		e_displaying = 5,
		e_dragging = 6,
	};

	// inline functions
	MxU32 GetLookupIndex();
	void StopPlayingActorScript();

	ResetPlacedSelectedPart m_resetPlacedSelectedPart; // 0xf8
	MxS16 m_rotateBuild;                               // 0xfc
	MxS32 m_clickState;                                // 0x100
	undefined4 m_unk0x104;                             // 0x104

	// name verified by BETA10 0x1006ebba
	MxS8 m_numAnimsRun; // 0x108

	MxU8 m_missclickCounter;                                  // 0x109
	MxU16 m_lastActorScript;                                  // 0x10a
	MxULong m_lastActorScriptStartTime;                       // 0x10c
	LegoROI* m_selectedPart;                                  // 0x110
	BoundingSphere m_targetBoundingSphere;                    // 0x114
	MxMatrix m_originalSelectedPartTransform;                 // 0x12c
	MxBool m_alreadyFinished;                                 // 0x174
	MxMatrix m_selectedPartStartTransform;                    // 0x178
	MxMatrix m_displayTransform;                              // 0x1c0
	MxMatrix m_selectedPartTargetTransform;                   // 0x208
	MxS32 m_selectedPartStartMousePosition[2];                // 0x250
	LegoCarBuildAnimPresenter* m_animPresenter;               // 0x258
	MxQuaternionTransformer m_draggingQuarternionTransformer; // 0x25c
	MxS32 m_selectedPartStartScreenPosition[2];               // 0x290
	MxS32 m_selectedPartTargetScreenPosition[2];              // 0x298
	MxFloat m_normalizedDistance;                             // 0x2a0
	Mx4DPointFloat m_selectedPartStartPosition;               // 0x2a4
	Mx4DPointFloat m_selectedPartTargetPosition;              // 0x2bc
	MxBool m_displayedPartIsPlaced;                           // 0x2d4

	// variable names verified by BETA10 0x1006b27a
	MxStillPresenter* m_ColorBook_Bitmap; // 0x2dc
	MxControlPresenter* m_Yellow_Ctl;     // 0x2e0
	MxControlPresenter* m_Red_Ctl;        // 0x2e4
	MxControlPresenter* m_Blue_Ctl;       // 0x2e8
	MxControlPresenter* m_Green_Ctl;      // 0x2ec
	MxControlPresenter* m_Gray_Ctl;       // 0x2f0
	MxControlPresenter* m_Black_Ctl;      // 0x2f4
	MxSoundPresenter* m_Shelf_Sound;      // 0x2f8
	MxSoundPresenter* m_PlaceBrick_Sound; // 0x2fc
	MxSoundPresenter* m_GetBrick_Sound;   // 0x300
	MxSoundPresenter* m_Paint_Sound;      // 0x304
	MxSoundPresenter* m_Decal_Sound;      // 0x308
	MxStillPresenter* m_Decal_Bitmap;     // 0x30c
	MxControlPresenter* m_Decals_Ctl;     // 0x310
	MxControlPresenter* m_Decals_Ctl1;    // 0x314
	MxControlPresenter* m_Decals_Ctl2;    // 0x318
	MxControlPresenter* m_Decals_Ctl3;    // 0x31c
	MxControlPresenter* m_Decals_Ctl4;    // 0x320
	MxControlPresenter* m_Decals_Ctl5;    // 0x324
	MxControlPresenter* m_Decals_Ctl6;    // 0x328
	MxControlPresenter* m_Decals_Ctl7;    // 0x32c

	// variable name verified by BETA10 0x1006b219
	LegoVehicleBuildState* m_buildState; // 0x32c

	// variable name verified by BETA10 0x1006d742
	MxS32 m_carId; // 0x330

	// variable name verified by BETA10 0x1006cba7
	LegoGameState::Area m_destLocation; // 0x334

	MxPresenter* m_jukeboxPresenter;      // 0x338
	MxControlPresenter* m_tickledControl; // 0x33c
	undefined4 m_unk0x340;                // 0x340
	MxS32 m_playingActorScript;           // 0x344
	MxU8 m_presentersEnabled;             // 0x348

	static MxS16 g_lastTickleState;
	static MxFloat g_selectedPartRotationAngleStepYAxis;
	static MxFloat g_rotationAngleStepYAxis;
	static LookupTableActions g_actorScripts[];
};

#endif // LEGOCARBUILD_H
