#ifndef MXTRANSITIONMANAGER_H
#define MXTRANSITIONMANAGER_H

#include "legoomni.h"
#include "mxcore.h"
#include "mxvideopresenter.h"

#include <ddraw.h>

// VTABLE: LEGO1 0x100d7ea0
class MxTransitionManager : public MxCore {
public:
	MxTransitionManager();
	virtual ~MxTransitionManager() override; // vtable+0x0

	__declspec(dllexport) void SetWaitIndicator(MxVideoPresenter* p_waitIndicator);

	virtual MxResult Tickle(); // vtable+0x8

	// FUNCTION: LEGO1 0x1004b950
	inline virtual const char* ClassName() const override // vtable+0x0c
	{
		return "MxTransitionManager";
	}

	// FUNCTION: LEGO1 0x1004b960
	inline virtual MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, MxTransitionManager::ClassName()) || MxCore::IsA(p_name);
	}

	virtual MxResult GetDDrawSurfaceFromVideoManager(); // vtable+0x14

	enum TransitionType {
		NOT_TRANSITIONING,
		NO_ANIMATION,
		DISSOLVE,
		PIXELATION,
		SCREEN_WIPE,
		WINDOWS,
		BROKEN // Unknown what this is supposed to be, it locks the game up
	};

	MxResult StartTransition(TransitionType p_animationType, MxS32 p_speed, MxBool p_doCopy, MxBool p_playMusicInAnim);

private:
	void EndTransition(MxBool p_notifyWorld);
	void Transition_None();
	void Transition_Dissolve();
	void Transition_Pixelation();
	void Transition_Wipe();
	void Transition_Windows();
	void Transition_Broken();

	void SubmitCopyRect(LPDDSURFACEDESC ddsc);
	void SetupCopyRect(LPDDSURFACEDESC ddsc);

	MxVideoPresenter* m_waitIndicator;
	RECT m_copyRect;
	MxU8* m_copyBuffer;

	flag_bitfield m_copyFlags;
	undefined4 m_unk0x24;
	flag_bitfield m_unk0x28;

	TransitionType m_transitionType;
	LPDIRECTDRAWSURFACE m_ddSurface;
	MxU16 m_animationTimer;
	MxU16 m_columnOrder[640]; // 0x36
	MxU16 m_randomShift[480]; // 0x536
	MxULong m_systemTime;     // 0x8f8
	MxS32 m_animationSpeed;   // 0x8fc
};

#endif // MXTRANSITIONMANAGER_H
