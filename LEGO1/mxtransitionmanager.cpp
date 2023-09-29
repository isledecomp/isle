#include "mxtransitionmanager.h"

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

// OFFSET: LEGO1 0x1004bac0 STUB
MxResult MxTransitionManager::Tickle()
{
  // TODO

  return 0;
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
                                              MxU8 p_unk, MxBool p_playMusicInAnim)
{
    // TODO: Incomplete and far from matching

    if (this->m_transitionType == NOT_TRANSITIONING) {
        if (!p_playMusicInAnim) {
            MxBackgroundAudioManager *backgroundAudioManager = BackgroundAudioManager();
            backgroundAudioManager->Stop();
        }
        this->m_transitionType = p_animationType;

        // TODO: This part of the function is mangled and I can't make out what it's doing right now

        MxU32 time = timeGetTime();
        this->m_systemTime = time;

        this->m_animationSpeed = p_speed;

        MxTickleManager *tickleManager = TickleManager();
        tickleManager->RegisterClient(this, p_speed);

        LegoInputManager *inputManager = InputManager();
        inputManager->m_unk88 = TRUE;
        inputManager->m_unk336 = FALSE;

        MxVideoManager *videoManager = VideoManager();
        videoManager->SetUnkE4(FALSE);

        SetAppCursor(1);
        return SUCCESS;
    }
    return FAILURE;
}