#ifndef LEGOCARBUILD_H
#define LEGOCARBUILD_H

#include "legostate.h"
#include "legoworld.h"

class LegoCarBuildAnimPresenter;
class MxControlPresenter;
class MxStillPresenter;
class MxSoundPresenter;

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

	// FUNCTION: LEGO1 0x10022950
	MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, LegoCarBuild::ClassName()) || LegoWorld::IsA(p_name);
	}

	MxLong Notify(MxParam& p_param) override;                                                             // vtable+0x04
	MxResult Tickle() override;                                                                           // vtable+0x08
	MxResult Create(MxDSAction& p_dsAction) override;                                                     // vtable+0x18
	void ReadyWorld() override;                                                                           // vtable+0x50
	MxBool VTable0x5c() override;                                                                         // vtable+0x5c
	MxBool Escape() override;                                                                             // vtable+0x64
	void Enable(MxBool p_enable) override;                                                                // vtable+0x68
	virtual void VTable0x6c();                                                                            // vtable+0x6c
	virtual void VTable0x70();                                                                            // vtable+0x70
	virtual void VTable0x74(MxFloat param_1[3], MxFloat param_2[3]);                                      // vtable+0x74
	virtual void VTable0x78(MxFloat param_1[3], MxFloat param_2[3]);                                      // vtable+0x78
	virtual void VTable0x7c(MxFloat param_1[3], MxFloat param_2[3]);                                      // vtable+0x7c
	virtual void VTable0x80(MxFloat param_1[2], MxFloat param_2[2], MxFloat param_3, MxFloat param_4[2]); // vtable+0x80

	void InitPresenters();
	void FUN_10022f30();
	void FUN_10024ef0();
	void FUN_10024f50();
	void SetPresentersEnabled(MxBool p_enabled);
	void TogglePresentersEnabled();
	undefined4 FUN_10025720(undefined4 param_1);
	MxS32 FUN_10025d70();
	void FUN_10025db0(const char* param_1, undefined4 param_2);
	MxS32 FUN_10025ee0(undefined4 param_1);

	// SYNTHETIC: LEGO1 0x10022a60
	// LegoCarBuild::`scalar deleting destructor'

private:
	undefined4 m_unk0xf8;                  // 0xf8
	MxS16 m_unk0xfc;                       // 0xfc
	undefined m_unk0xfe[2];                // 0xfe
	undefined4 m_unk0x100;                 // 0x100
	undefined4 m_unk0x104;                 // 0x104
	undefined m_unk0x108;                  // 0x108
	undefined m_unk0x109;                  // 0x109
	MxU16 m_unk0x10a;                      // 0x10a
	DWORD m_unk0x10c;                      // 0x10c
	LegoROI* m_unk0x110;                   // 0x110
	Mx3DPointFloat m_unk0x114;             // 0x114
	undefined4 m_unk0x128;                 // 0x128
	MxMatrix m_unk0x12c;                   // 0x12c
	undefined m_unk0x174;                  // 0x174
	MxMatrix m_unk0x178;                   // 0x178
	MxMatrix m_unk0x1c0;                   // 0x1c0
	MxMatrix m_unk0x208;                   // 0x208
	undefined m_unk0x250[0x08];            // 0x250
	LegoCarBuildAnimPresenter* m_unk0x258; // 0x258
	UnknownMx4DPointFloat m_unk0x25c;      // 0x25c

	// These four are likely locations in pixel space
	MxS32 m_unk0x290; // 0x290
	MxS32 m_unk0x294; // 0x294
	MxS32 m_unk0x298; // 0x298
	MxS32 m_unk0x29c; // 0x29c

	MxFloat m_unk0x2a0;                  // 0x2a0
	Mx4DPointFloat m_unk0x2a4;           // 0x2a4
	Mx4DPointFloat m_unk0x2bc;           // 0x2bc
	MxBool m_unk0x2d4;                   // 0x2d4
	MxStillPresenter* m_colorBookBitmap; // 0x2dc
	MxControlPresenter* m_yellowCtl;     // 0x2e0
	MxControlPresenter* m_redCtl;        // 0x2e4
	MxControlPresenter* m_BlueCtl;       // 0x2e8
	MxControlPresenter* m_GreenCtl;      // 0x2ec
	MxControlPresenter* m_GrayCtl;       // 0x2f0
	MxControlPresenter* m_BlackCtl;      // 0x2f4
	MxSoundPresenter* m_shelfSound;      // 0x2f8
	MxSoundPresenter* m_placeBrickSound; // 0x2fc
	MxSoundPresenter* m_getBrickSound;   // 0x300
	MxSoundPresenter* m_paintSound;      // 0x304
	MxSoundPresenter* m_decalSound;      // 0x308
	MxStillPresenter* m_decalBitmap;     // 0x30c
	MxControlPresenter* m_decalsCtl0;    // 0x310
	MxControlPresenter* m_decalsCtl1;    // 0x314
	MxControlPresenter* m_decalsCtl2;    // 0x318
	MxControlPresenter* m_decalsCtl3;    // 0x31c
	MxControlPresenter* m_decalsCtl4;    // 0x320
	MxControlPresenter* m_decalsCtl5;    // 0x324
	MxControlPresenter* m_decalsCtl6;    // 0x328
	MxControlPresenter* m_decalsCtl7;    // 0x32c

	// variable name verified by BETA10 0x1006b219
	LegoVehicleBuildState* m_buildState; // 0x32c

	undefined4 m_unk0x330;          // 0x330
	undefined4 m_unk0x334;          // 0x334
	undefined4 m_unk0x338;          // 0x338
	MxControlPresenter* m_unk0x33c; // 0x33c
	undefined4 m_unk0x340;          // 0x340
	undefined4 m_unk0x344;          // 0x344
	MxU8 m_presentersEnabled;       // 0x348

	// GLOBAL: LEGO1 0x100f11cc
	static MxS16 g_unk0x100f11cc;
};

#endif // LEGOCARBUILD_H
