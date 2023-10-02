#include "mxtransitionmanager.h"

#include "legovideomanager.h"
#include "legoinputmanager.h"
#include "legoutil.h"
#include "mxticklemanager.h"
#include "mxbackgroundaudiomanager.h"

DECOMP_SIZE_ASSERT(MxTransitionManager, 0x900);

// OFFSET: LEGO1 0x1004b8d0
MxTransitionManager::MxTransitionManager()
{
  m_animationTimer = 0;
  m_transitionType = NOT_TRANSITIONING;
  m_ddSurface = NULL;
  m_unk08 = 0;
  m_unk1c = 0;
  m_unk20.bit0 = FALSE;
  m_unk28.bit0 = FALSE;
  m_unk24 = 0;
}

// OFFSET: LEGO1 0x1004ba00
MxTransitionManager::~MxTransitionManager()
{
  free(m_unk1c);

  if (m_unk08 != NULL) {
    delete m_unk08->m_unk1c;
    delete m_unk08;
  }

  TickleManager()->UnregisterClient(this);
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
                                              MxBool p_unk, MxBool p_playMusicInAnim)
{
  if (this->m_transitionType == NOT_TRANSITIONING) {
    if (!p_playMusicInAnim) {
      MxBackgroundAudioManager *backgroundAudioManager = BackgroundAudioManager();
      backgroundAudioManager->Stop();
    }

    this->m_transitionType = p_animationType;

    m_unk20.bit0 = p_unk;

    if (m_unk20.bit0 && m_unk08 != NULL) {
      m_unk08->vtable54(1);

      MxTransitionManagerUnknownSubclass2 *iVar2 = m_unk08->m_unk1c;
      iVar2->m_unk3c = 10000;
      iVar2->m_unk30 |= 0x200;
    }

    MxU32 time = timeGetTime();
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
