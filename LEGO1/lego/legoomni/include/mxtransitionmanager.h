#ifndef MXTRANSITIONMANAGER_H
#define MXTRANSITIONMANAGER_H

#include "decomp.h"
#include "mxcore.h"

#include <ddraw.h>

class MxVideoPresenter;

// VTABLE: LEGO1 0x100d7ea0
// VTABLE: BETA10 0x101bf670
// SIZE 0x900
class MxTransitionManager : public MxCore {
public:
	MxTransitionManager();
	~MxTransitionManager() override; // vtable+0x00

	void SetWaitIndicator(MxVideoPresenter* p_waitIndicator);

	MxResult Tickle() override; // vtable+0x08

	// FUNCTION: LEGO1 0x1004b950
	// FUNCTION: BETA10 0x100ed8e0
	const char* ClassName() const override // vtable+0x0c
	{
		return "MxTransitionManager";
	}

	// FUNCTION: LEGO1 0x1004b960
	MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, MxTransitionManager::ClassName()) || MxCore::IsA(p_name);
	}

	virtual MxResult GetDDrawSurfaceFromVideoManager(); // vtable+0x14

	enum TransitionType {
		e_idle = 0, // name verified by BETA10 0x100ec4e6
		e_noAnimation,
		e_dissolve,
		e_mosaic,
		e_wipeDown,
		e_windows,
		e_broken // Unknown what this is supposed to be, it locks the game up
	};

	MxResult StartTransition(TransitionType p_animationType, MxS32 p_speed, MxBool p_doCopy, MxBool p_playMusicInAnim);

	TransitionType GetTransitionType() { return m_mode; }

	// SYNTHETIC: LEGO1 0x1004b9e0
	// MxTransitionManager::`scalar deleting destructor'

private:
	void EndTransition(MxBool p_notifyWorld);
	void NoTransition();
	void DissolveTransition();
	void MosaicTransition();
	void WipeDownTransition();
	void WindowsTransition();
	void BrokenTransition();

	void SubmitCopyRect(LPDDSURFACEDESC p_ddsc);
	void SetupCopyRect(LPDDSURFACEDESC p_ddsc);

	MxVideoPresenter* m_waitIndicator; // 0x08
	RECT m_copyRect;                   // 0x0c
	MxU8* m_copyBuffer;                // 0x1c
	FlagBitfield m_copyFlags;          // 0x20
	undefined4 m_unk0x24;              // 0x24
	FlagBitfield m_unk0x28;            // 0x28

	// name verified by BETA10 0x100ec4e6
	TransitionType m_mode; // 0x2c

	LPDIRECTDRAWSURFACE m_ddSurface; // 0x30
	MxU16 m_animationTimer;          // 0x34
	MxU16 m_columnOrder[640];        // 0x36
	MxU16 m_randomShift[480];        // 0x536
	MxULong m_systemTime;            // 0x8f8
	MxS32 m_animationSpeed;          // 0x8fc
};

#endif // MXTRANSITIONMANAGER_H
