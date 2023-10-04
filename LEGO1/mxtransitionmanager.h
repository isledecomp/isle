#ifndef MXTRANSITIONMANAGER_H
#define MXTRANSITIONMANAGER_H

#include "mxcore.h"
#include "mxvideopresenter.h"
#include "legoomni.h"

// VTABLE 0x100d7ea0
class MxTransitionManager : public MxCore
{
public:
  MxTransitionManager();
  virtual ~MxTransitionManager() override; // vtable+0x0

  __declspec(dllexport) void SetWaitIndicator(MxVideoPresenter *videoPresenter);

  virtual MxResult Tickle(); // vtable+0x8

  // OFFSET: LEGO1 0x1004b950
  inline virtual const char *ClassName() const override // vtable+0x0c
  {
    return "MxTransitionManager";
  }

  // OFFSET: LEGO1 0x1004b960
  inline virtual MxBool IsA(const char *name) const override // vtable+0x10
  {
    return !strcmp(name, MxTransitionManager::ClassName()) || MxCore::IsA(name);
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
  void EndTransition(MxBool);
  void Transition_Dissolve();
  void SubmitCopyRect(DDSURFACEDESC &);
  void SetupCopyRect(DDSURFACEDESC &);

  MxVideoPresenter *m_waitIndicator;
  RECT m_copyRect;
  void *m_copyBuffer;

  flag_bitfield m_copyFlags;
  undefined4 m_unk24;
  flag_bitfield m_unk28;

  TransitionType m_transitionType;
  LPDIRECTDRAWSURFACE m_ddSurface;
  MxU16 m_animationTimer;
  MxU16 m_columnOrder[640]; // 0x36
  MxU16 m_randomShift[480]; // 0x536
  MxULong m_systemTime;
  MxS32 m_animationSpeed;
};

#endif // MXTRANSITIONMANAGER_H
