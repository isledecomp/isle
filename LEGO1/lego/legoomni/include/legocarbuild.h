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
		e_unknown0 = 0,
		e_entering = 1,
		e_unknown2 = 2,
		e_cutscene = 3,
		e_unknown4 = 4,
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
	MxU8 m_unk0x4c;                  // 0x4c
	MxBool m_unk0x4d;                // 0x4d
	MxBool m_unk0x4e;                // 0x4e
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
		undefined4 m_unk0x00; // 0x00
		undefined4 m_unk0x04; // 0x04
		undefined4 m_unk0x08; // 0x08
		undefined4 m_unk0x0c; // 0x0c
		undefined4 m_unk0x10; // 0x10
		undefined4 m_unk0x14; // 0x14
		undefined4 m_unk0x18; // 0x18
	};

	enum Unknown0xf8 {
		c_unknownminusone = -1,
		c_unknown8 = 8
	};

	LegoCarBuild();
	~LegoCarBuild() override;

	// FUNCTION: LEGO1 0x10022930
	// FUNCTION: BETA10 0x10070070
	MxBool EnabledAfterDestruction() override { return TRUE; } // vtable+0x5c

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

	MxResult Create(MxDSAction& p_dsAction) override;                  // vtable+0x18
	void ReadyWorld() override;                                        // vtable+0x50
	MxBool Escape() override;                                          // vtable+0x64
	void Enable(MxBool p_enable) override;                             // vtable+0x68
	virtual void VTable0x6c();                                         // vtable+0x6c
	virtual void VTable0x70();                                         // vtable+0x70
	virtual void VTable0x74(MxFloat p_param1[2], MxFloat p_param2[3]); // vtable+0x74
	virtual void VTable0x78(MxFloat p_param1[2], MxFloat p_param2[3]); // vtable+0x78
	virtual void VTable0x7c(MxFloat p_param1[2], MxFloat p_param2[3]); // vtable+0x7c
	virtual void VTable0x80(
		MxFloat p_param1[2],
		MxFloat p_param2[2],
		MxFloat p_param3,
		MxFloat p_param4[2]
	); // vtable+0x80

	MxS16 GetPlacedPartCount();
	void SetPlacedPartCount(MxU8 p_placedPartCount);
	void InitPresenters();
	void FUN_10022f00();
	void FUN_10022f30();
	void FUN_10023130(MxLong p_x, MxLong p_y);
	void AddSelectedPartToBuild();
	undefined4 FUN_10024250(LegoEventNotificationParam* p_param);
	void FUN_100243a0();
	undefined4 FUN_10024480(MxActionNotificationParam* p_param);
	undefined4 SelectPartFromMousePosition(MxLong p_x, MxLong p_y);
	undefined4 FUN_100246e0(MxLong p_x, MxLong p_y);
	MxS32 FUN_10024850(MxLong p_x, MxLong p_y);
	undefined4 FUN_10024890(MxParam* p_param);
	undefined4 FUN_10024c20(MxNotificationParam* p_param);
	void FUN_10024ef0();
	void FUN_10024f30();
	void FUN_10024f50();
	void FUN_10024f70(MxBool p_enabled);
	void SetPresentersEnabled(MxBool p_enabled);
	void TogglePresentersEnabled();
	void FUN_100250e0(MxBool p_param);
	void FUN_10025350(MxS32 p_objectId);
	void FUN_10025450();
	void FUN_10025720(undefined4 p_param1);
	void FUN_10025d10(MxS32 p_param);
	MxS32 FUN_10025d70();
	void FUN_10025db0(const char* p_param1, undefined4 p_param2);
	void FUN_10025e40();
	MxS32 FUN_10025ee0(undefined4 p_param1);

	// FUNCTION: BETA10 0x100735b0
	void SetCarBuildAnimPresenter(LegoCarBuildAnimPresenter* p_animPresenter) { m_animPresenter = p_animPresenter; }

	// SYNTHETIC: LEGO1 0x10022a60
	// LegoCarBuild::`scalar deleting destructor'

private:
	// inline functions
	MxU32 Beta0x10070520();
	void StopActionIn0x344();

	Unknown0xf8 m_unk0xf8; // 0xf8
	MxS16 m_unk0xfc;       // 0xfc
	MxS32 m_unk0x100;      // 0x100
	undefined4 m_unk0x104; // 0x104

	// name verified by BETA10 0x1006ebba
	MxS8 m_numAnimsRun; // 0x108

	MxU8 m_unk0x109;           // 0x109
	MxU16 m_unk0x10a;          // 0x10a
	DWORD m_unk0x10c;          // 0x10c
	LegoROI* m_selectedPart;   // 0x110
	BoundingSphere m_unk0x114; // 0x114
	MxMatrix m_unk0x12c;       // 0x12c
	undefined m_unk0x174;      // 0x174
	MxMatrix m_unk0x178;       // 0x178
	MxMatrix m_unk0x1c0;       // 0x1c0
	MxMatrix m_unk0x208;       // 0x208

	// This is likely a location in pixel space
	MxS32 m_unk0x250[2]; // 0x250

	LegoCarBuildAnimPresenter* m_animPresenter; // 0x258
	MxQuaternionTransformer m_unk0x25c;         // 0x25c

	// These two are likely locations in pixel space
	MxS32 m_unk0x290[2]; // 0x290
	MxS32 m_unk0x298[2]; // 0x298

	MxFloat m_unk0x2a0;            // 0x2a0
	Mx4DPointFloat m_unk0x2a4;     // 0x2a4
	Mx4DPointFloat m_unk0x2bc;     // 0x2bc
	MxBool m_selectedPartIsPlaced; // 0x2d4

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
	undefined4 m_carId; // 0x330

	// variable name verified by BETA10 0x1006cba7
	LegoGameState::Area m_destLocation; // 0x334

	MxPresenter* m_unk0x338;        // 0x338
	MxControlPresenter* m_unk0x33c; // 0x33c
	undefined4 m_unk0x340;          // 0x340
	undefined4 m_unk0x344;          // 0x344
	MxU8 m_presentersEnabled;       // 0x348

	static MxS16 g_unk0x100f11cc;
	static MxFloat g_unk0x100d65a4;
	static MxFloat g_rotationAngleStepYAxis;
	static LookupTableActions g_unk0x100d65b0[];
};

#endif // LEGOCARBUILD_H
