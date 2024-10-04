#ifndef LEGOCARBUILD_H
#define LEGOCARBUILD_H

#include "legogamestate.h"
#include "legostate.h"
#include "legoworld.h"

class LegoCarBuildAnimPresenter;
class LegoEventNotificationParam;
class MxControlPresenter;
class MxStillPresenter;
class MxSoundPresenter;
class MxActionNotificationParam;

// VTABLE: LEGO1 0x100d66e0
// SIZE 0x50
class LegoVehicleBuildState : public LegoState {
public:
	LegoVehicleBuildState(const char* p_classType);

	// FUNCTION: LEGO1 0x10025ff0
	const char* ClassName() const override // vtable+0x0c
	{
		return this->m_className.GetData();
	}

	// FUNCTION: LEGO1 0x10026000
	MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, this->m_className.GetData()) || LegoState::IsA(p_name);
	}

	MxResult Serialize(LegoFile* p_file) override; // vtable+0x1c

	// SYNTHETIC: LEGO1 0x100260a0
	// LegoVehicleBuildState::`scalar deleting destructor'

	// TODO: Most likely getters/setters are not used according to BETA.

	Playlist m_unk0x08[4]; // 0x08

	// This can be one of the following:
	// * LegoRaceCarBuildState
	// * LegoCopterBuildState
	// * LegoDuneCarBuildState
	// * LegoJetskiBuildState
	MxString m_className; // 0x38

	// Known States:
	// * 1 == enter(ing) build screen
	// * 3 == cutscene/dialogue
	// * 6 == exit(ing) build screen
	MxU32 m_animationState; // 0x48
	undefined m_unk0x4c;    // 0x4c
	MxBool m_unk0x4d;       // 0x4d
	MxBool m_unk0x4e;       // 0x4e
	MxU8 m_placedPartCount; // 0x4f
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
	LegoCarBuild();
	~LegoCarBuild() override;

	// FUNCTION: LEGO1 0x10022940
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
	MxBool VTable0x5c() override;                                      // vtable+0x5c
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

	void InitPresenters();
	void FUN_10022f30();
	void FUN_10023130(MxLong p_x, MxLong p_y);
	undefined4 FUN_10024250(LegoEventNotificationParam* p_param);
	void FUN_100243a0();
	undefined4 FUN_10024480(MxActionNotificationParam* p_param);
	undefined4 FUN_100244e0(MxLong p_x, MxLong p_y);
	undefined4 FUN_100246e0(MxLong p_x, MxLong p_y);
	MxS32 FUN_10024850(MxLong p_x, MxLong p_y);
	undefined4 FUN_10024890(LegoEventNotificationParam* p_param);
	void FUN_10024c20(LegoEventNotificationParam* p_param);
	void FUN_10024ef0();
	void FUN_10024f50();
	void FUN_10024f70(MxBool p_enabled);
	void SetPresentersEnabled(MxBool p_enabled);
	void TogglePresentersEnabled();
	void FUN_100250e0(MxBool p_param);
	void FUN_10025450();
	undefined4 FUN_10025720(undefined4 p_param1);
	MxS32 FUN_10025d70();
	void FUN_10025db0(const char* p_param1, undefined4 p_param2);
	void FUN_10025e40();
	MxS32 FUN_10025ee0(undefined4 p_param1);

	// SYNTHETIC: LEGO1 0x10022a60
	// LegoCarBuild::`scalar deleting destructor'

private:
	undefined4 m_unk0xf8;      // 0xf8
	MxS16 m_unk0xfc;           // 0xfc
	undefined m_unk0xfe[2];    // 0xfe
	MxS32 m_unk0x100;          // 0x100
	undefined4 m_unk0x104;     // 0x104
	MxS8 m_unk0x108;           // 0x108
	MxU8 m_unk0x109;           // 0x109
	MxU16 m_unk0x10a;          // 0x10a
	DWORD m_unk0x10c;          // 0x10c
	LegoROI* m_unk0x110;       // 0x110
	BoundingSphere m_unk0x114; // 0x114
	MxMatrix m_unk0x12c;       // 0x12c
	undefined m_unk0x174;      // 0x174
	MxMatrix m_unk0x178;       // 0x178
	MxMatrix m_unk0x1c0;       // 0x1c0
	MxMatrix m_unk0x208;       // 0x208

	// This is likely a location in pixel space
	MxS32 m_unk0x250[2]; // 0x250

	LegoCarBuildAnimPresenter* m_unk0x258; // 0x258
	UnknownMx4DPointFloat m_unk0x25c;      // 0x25c

	// These two are likely locations in pixel space
	MxS32 m_unk0x290[2]; // 0x290
	MxS32 m_unk0x298[2]; // 0x298

	MxFloat m_unk0x2a0;        // 0x2a0
	Mx4DPointFloat m_unk0x2a4; // 0x2a4
	Mx4DPointFloat m_unk0x2bc; // 0x2bc
	MxBool m_unk0x2d4;         // 0x2d4

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

	undefined4 m_unk0x330; // 0x330

	// variable name verified by BETA10 0x1006cba7
	LegoGameState::Area m_destLocation; // 0x334

	undefined4 m_unk0x338;          // 0x338
	MxControlPresenter* m_unk0x33c; // 0x33c
	undefined4 m_unk0x340;          // 0x340
	undefined4 m_unk0x344;          // 0x344
	MxU8 m_presentersEnabled;       // 0x348

	static MxS16 g_unk0x100f11cc;
	static MxFloat g_unk0x100d65a4;
	static MxFloat g_rotationAngleStepYAxis;
};

#endif // LEGOCARBUILD_H
