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

  MxResult StartTransition(TransitionType p_animationType, MxS32 p_speed, undefined p_unk, MxBool p_playMusicInAnim);

  void MxTransitionManager::EndTransition(MxBool p_unk);

  void FUN_1004bcf0();
  void FUN_1004bd10();
  void FUN_1004bed0();
  void FUN_1004c170();
  void FUN_1004c270();
  void FUN_1004c3e0();


private:
  undefined m_pad00[0x20];
  undefined m_pad20[0x04];
  TransitionType m_transitionType;
  LPDIRECTDRAWSURFACE m_ddSurface;
  MxU16 m_animationTimer;
  undefined m_pad36[0x8c2];
  MxULong m_systemTime;
  MxS32 m_animationSpeed;
};

#endif // MXTRANSITIONMANAGER_H
