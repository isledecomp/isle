#ifndef LEGOANIMMMPRESENTER_H
#define LEGOANIMMMPRESENTER_H

// MxDSActionListCursor needs to be included before std::list
// clang-format off
#include "mxdsmultiaction.h"
// clang-format on
#include "mxcompositepresenter.h"

class LegoAnimPresenter;
class LegoWorld;
class LegoROI;
struct LegoTranInfo;
class MxMatrix;

// VTABLE: LEGO1 0x100d7de8
// SIZE 0x74
class LegoAnimMMPresenter : public MxCompositePresenter {
public:
	enum {
		e_unk0,
		e_unk1,
		e_unk2,
		e_unk3,
		e_unk4,
		e_unk5,
		e_unk6,
		e_unk7
	};

	LegoAnimMMPresenter();
	~LegoAnimMMPresenter() override;

	MxLong Notify(MxParam& p_param) override; // vtable+0x04

	// FUNCTION: BETA10 0x1004d840
	static const char* HandlerClassName()
	{
		// STRING: LEGO1 0x100f046c
		return "LegoAnimMMPresenter";
	}

	// FUNCTION: LEGO1 0x1004a950
	// FUNCTION: BETA10 0x1004d810
	const char* ClassName() const override // vtable+0x0c
	{
		return HandlerClassName();
	}

	// FUNCTION: LEGO1 0x1004a960
	MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, LegoAnimMMPresenter::ClassName()) || MxCompositePresenter::IsA(p_name);
	}

	void ReadyTickle() override;                                                           // vtable+0x18
	void StartingTickle() override;                                                        // vtable+0x1c
	void StreamingTickle() override;                                                       // vtable+0x20
	void RepeatingTickle() override;                                                       // vtable+0x24
	void DoneTickle() override;                                                            // vtable+0x2c
	void ParseExtra() override;                                                            // vtable+0x30
	MxResult StartAction(MxStreamController* p_controller, MxDSAction* p_action) override; // vtable+0x3c
	void EndAction() override;                                                             // vtable+0x40
	void AdvanceSerialAction(MxPresenter* p_presenter) override;                           // vtable+0x60

	// SYNTHETIC: LEGO1 0x1004aa40
	// LegoAnimMMPresenter::`scalar deleting destructor'
	MxBool HasPassedPresenterStart();
	void StopAndFinishAnimation();
	MxBool UsesLocalActors();
	void ReleaseUserActor();

	LegoAnimPresenter* GetPresenter() { return m_presenter; }

private:
	MxBool RunStartupSequence();
	MxBool CaptureAnimationState(MxLong p_time);
	MxBool WaitForPreRoll(MxLong p_time);
	MxBool WaitForTransitionSound(MxLong p_time);
	MxBool RestoreInitialTransforms(MxLong p_time);
	MxBool PreparePresentersForStart(MxLong p_time);
	MxBool StartChildPresenters(MxLong p_time);
	MxBool WaitForAnimationPresenterIdle(MxLong p_time);
	MxBool RestoreUserActorAfterAnimation(MxLong p_time);

	LegoAnimPresenter* m_presenter; // 0x4c
	MxLong m_unk0x50;               // 0x50
	undefined4 m_unk0x54;           // 0x54
	MxU8 m_unk0x58;                 // 0x58
	MxU8 m_unk0x59;                 // 0x59
	MxU32 m_animmanId;              // 0x5c
	LegoTranInfo* m_tranInfo;       // 0x60
	LegoWorld* m_world;             // 0x64
	MxMatrix* m_unk0x68;            // 0x68
	LegoROI** m_roiMap;             // 0x6c
	MxU32 m_roiMapSize;             // 0x70
};

#endif // LEGOANIMMMPRESENTER_H
