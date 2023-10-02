#include "mxtransitionmanager.h"
#include "legoutil.h"
#include "legovideomanager.h"

DECOMP_SIZE_ASSERT(MxTransitionManager, 0x900);

// 0x100f4378
RECT g_rect_100f4378 = {0, 0, 640, 480};

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

// OFFSET: LEGO1 0x1004bc30 STUB
void MxTransitionManager::EndTransition(MxBool)
{
  // TODO
}

// OFFSET: LEGO1 0x1004bd10
void MxTransitionManager::Transition_Dissolve()
{
  // If the animation is finished
  if (m_animationTimer == 40) {
    m_animationTimer = 0;
    EndTransition(TRUE);
    return;
  }

  // If we are starting the animation
  if (m_animationTimer == 0) {
    // Populate
    for (int i = 0; i < 640; i++) {
      m_pad36[i] = i;
    }

    // Randomize (sorta)
    for (i = 0; i < 640; i++) {
      int swap_ofs = rand() % 640;
      undefined2 t = m_pad36[i];
      m_pad36[i] = m_pad36[swap_ofs];
      m_pad36[swap_ofs] = t;
    }

    for (i = 0; i < 480; i++) {
      m_pad536[i] = rand() % 640;
    }
  }

  // Else run one tick of the animation
  DDSURFACEDESC ddsd;
  memset(&ddsd, 0, sizeof(ddsd));
  ddsd.dwSize = sizeof(ddsd);

  HRESULT res = m_ddSurface->Lock(NULL, &ddsd, 1, NULL);
  if (res == DDERR_SURFACELOST) {
    m_ddSurface->Restore();
    res = m_ddSurface->Lock(NULL, &ddsd, 1, NULL);
  }

  if (res == DD_OK) {
    FUN_1004c4d0(&ddsd);

    for (int i = 0; i < 640; i++) {
      if (m_animationTimer * 16 > m_pad36[i])
        continue;

      if (m_animationTimer * 16 + 15 < m_pad36[i])
        continue;

      for (int j = 0; j < 480; j++) {
        int jt = (m_pad536[j] + i) % 640;

        if (ddsd.ddpfPixelFormat.dwRGBBitCount == 8) {
          MxU8 *pix = (MxU8*)ddsd.lpSurface;
          pix[j * ddsd.lPitch + jt] = 0;
        } else {
          MxU16 *pix = (MxU16*)ddsd.lpSurface;
          pix[j * ddsd.lPitch + jt] = 0;
        }
      }
    }

    FUN_1004c580(&ddsd);
    m_ddSurface->Unlock(ddsd.lpSurface);

    if (VideoManager()->GetVideoParam().flags().GetFlipSurfaces()) {
      LPDIRECTDRAWSURFACE surf = VideoManager()->GetDisplaySurface()->GetDirectDrawSurface1();
      surf->BltFast(NULL, NULL, m_ddSurface, &g_rect_100f4378, 0x10);
    }

    m_animationTimer++;
  }
}

// OFFSET: LEGO1 0x1004c470 STUB
void MxTransitionManager::SetWaitIndicator(MxVideoPresenter *videoPresenter)
{
  // TODO
}

// OFFSET: LEGO1 0x1004c4d0 STUB
void MxTransitionManager::FUN_1004c4d0(DDSURFACEDESC *ddsc)
{
  // TODO
}

// OFFSET: LEGO1 0x1004c580 STUB
void MxTransitionManager::FUN_1004c580(DDSURFACEDESC *ddsc)
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
