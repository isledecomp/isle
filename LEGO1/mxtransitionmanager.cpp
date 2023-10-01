#include "mxtransitionmanager.h"
#include "legoutil.h"
#include "legovideomanager.h"

DECOMP_SIZE_ASSERT(MxTransitionManager, 0x900);

// OFFSET: LEGO1 0x1004b8d0 STUB
MxTransitionManager::MxTransitionManager()
{
  // TODO
}

// OFFSET: LEGO1 0x1004ba00 STUB
MxTransitionManager::~MxTransitionManager()
{
  // TODO
}

// OFFSET: LEGO1 0x1004bac0
MxResult MxTransitionManager::Tickle()
{
  MxS32 speed = this->m_animationSpeed;
  MxULong storedTime = this->m_systemTime;
  MxULong realTime = timeGetTime();

  if (speed + storedTime <= realTime) {
    storedTime = timeGetTime();
    this->m_systemTime = storedTime;

    switch (this->m_transitionType) {
      case NO_ANIMATION:
        FUN_1004bcf0();
        return SUCCESS;
      case DISSOLVE:
        FUN_1004bd10();
        return SUCCESS;
      case PIXELATION:
        FUN_1004bed0();
        return SUCCESS;
      case SCREEN_WIPE:
        FUN_1004c170();
        return SUCCESS;
      case WINDOWS:
        FUN_1004c270();
        return SUCCESS;
      case BROKEN:
        FUN_1004c3e0();
    }
    return SUCCESS;
  }
  return SUCCESS;
}

// OFFSET: LEGO1 0x1004c470 STUB
void MxTransitionManager::SetWaitIndicator(MxVideoPresenter *videoPresenter)
{
  // TODO
}

// OFFSET: LEGO1 0x1004baa0
MxResult MxTransitionManager::GetDDrawSurfaceFromVideoManager() // vtable+0x14
{
  LegoVideoManager *videoManager = VideoManager();
  this->m_ddSurface = videoManager->GetDisplaySurface()->GetDirectDrawSurface2();
  return SUCCESS;
}

// OFFSET: LEGO1 0x1004bb70
MxResult MxTransitionManager::StartTransition(TransitionType p_animationType, MxS32 p_speed,
                                              undefined p_unk, MxBool p_playMusicInAnim)
{
  // TODO: Incomplete and far from matching

  if (this->m_transitionType == NOT_TRANSITIONING) {
    if (!p_playMusicInAnim) {
      MxBackgroundAudioManager *backgroundAudioManager = BackgroundAudioManager();
      backgroundAudioManager->Stop();
    }
      this->m_transitionType = p_animationType;

      // TODO: This part of the function is mangled and I can't make out what it's doing right now

      MxULong time = timeGetTime();
      this->m_systemTime = time;

      this->m_animationSpeed = p_speed;

      MxTickleManager *tickleManager = TickleManager();
      tickleManager->RegisterClient(this, p_speed);

      LegoInputManager *inputManager = InputManager();
      inputManager->m_unk88 = TRUE;
      inputManager->m_unk336 = FALSE;

      LegoVideoManager *videoManager = VideoManager();
      videoManager->SetUnkE4(FALSE);

      SetAppCursor(1);
      return SUCCESS;
  }
  return FAILURE;
}

// OFFSET: LEGO1 0x1004bcf0 STUB
void MxTransitionManager::FUN_1004bcf0()
{
  // TODO
}

// OFFSET: LEGO1 0x1004bd10 STUB
void MxTransitionManager::FUN_1004bd10()
{
  // TODO
}

// OFFSET: LEGO1 0x1004bed0 STUB
void MxTransitionManager::FUN_1004bed0()
{
  // TODO
}

// OFFSET: LEGO1 0x1004c170 STUB
void MxTransitionManager::FUN_1004c170()
{
  // TODO
}

// OFFSET: LEGO1 0x1004c270 STUB
void MxTransitionManager::FUN_1004c270()
{
  // TODO
}

// OFFSET: LEGO1 0x1004c3e0 STUB
void MxTransitionManager::FUN_1004c3e0()
{
  // TODO
}
