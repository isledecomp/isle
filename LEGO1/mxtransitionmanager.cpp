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
  if (this->m_animationSpeed + this->m_systemTime > timeGetTime()) {
    return SUCCESS;
  }

  this->m_systemTime = timeGetTime();

  switch (this->m_transitionType) {
    case NO_ANIMATION:
      FUN_1004bcf0();
      break;
    case DISSOLVE:
      FUN_1004bd10();
      break;
    case PIXELATION:
      FUN_1004bed0();
      break;
    case SCREEN_WIPE:
      FUN_1004c170();
      break;
    case WINDOWS:
      FUN_1004c270();
      break;
    case BROKEN:
      FUN_1004c3e0();
      break;
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

// OFFSET: LEGO1 0x1004bc30 STUB
void MxTransitionManager::EndTransition(MxBool p_unk)
{
  // TODO
}

// OFFSET: LEGO1 0x1004bcf0
void MxTransitionManager::FUN_1004bcf0()
{
  LegoVideoManager *videoManager = VideoManager();
  videoManager->GetDisplaySurface()->FUN_100ba640();
  EndTransition(TRUE);
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
