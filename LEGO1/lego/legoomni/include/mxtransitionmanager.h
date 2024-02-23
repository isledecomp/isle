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
	~MxTransitionManager() override; // vtable+0x00

	void SetWaitIndicator(MxVideoPresenter* p_waitIndicator);

	MxResult Tickle() override; // vtable+0x08

	// FUNCTION: LEGO1 0x1004b950
	inline const char* ClassName() const override // vtable+0x0c
	{
		return "MxTransitionManager";
	}

	// FUNCTION: LEGO1 0x1004b960
	inline MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, MxTransitionManager::ClassName()) || MxCore::IsA(p_name);
	}

	virtual MxResult GetDDrawSurfaceFromVideoManager(); // vtable+0x14

	enum TransitionType {
		e_notTransitioning = 0,
		e_noAnimation,
		e_dissolve,
		e_pixelation,
		e_screenWipe,
		e_windows,
		e_broken // Unknown what this is supposed to be, it locks the game up
	};

	MxResult StartTransition(TransitionType p_animationType, MxS32 p_speed, MxBool p_doCopy, MxBool p_playMusicInAnim);

	inline TransitionType GetTransitionType() { return m_transitionType; }

	// SYNTHETIC: LEGO1 0x1004b9e0
	// MxTransitionManager::`scalar deleting destructor'

private:
	void EndTransition(MxBool p_notifyWorld);
	void TransitionNone();
	void TransitionDissolve();
	void TransitionPixelation();
	void TransitionWipe();
	void TransitionWindows();
	void TransitionBroken();

	void SubmitCopyRect(LPDDSURFACEDESC p_ddsc);
	void SetupCopyRect(LPDDSURFACEDESC p_ddsc);

	MxVideoPresenter* m_waitIndicator; // 0x08
	RECT m_copyRect;                   // 0x0c
	MxU8* m_copyBuffer;                // 0x1c
	FlagBitfield m_copyFlags;          // 0x20
	undefined4 m_unk0x24;              // 0x24
	FlagBitfield m_unk0x28;            // 0x28
	TransitionType m_transitionType;   // 0x2c
	LPDIRECTDRAWSURFACE m_ddSurface;   // 0x30
	MxU16 m_animationTimer;            // 0x34
	MxU16 m_columnOrder[640];          // 0x36
	MxU16 m_randomShift[480];          // 0x536
	MxULong m_systemTime;              // 0x8f8
	MxS32 m_animationSpeed;            // 0x8fc
};

#endif // MXTRANSITIONMANAGER_H
