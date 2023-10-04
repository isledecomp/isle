#include "mxtransitionmanager.h"
#include "legoutil.h"
#include "legovideomanager.h"

DECOMP_SIZE_ASSERT(MxTransitionManager, 0x900);

// 0x100f4378
RECT g_fullScreenRect = {0, 0, 640, 480};

// OFFSET: LEGO1 0x1004b8d0
MxTransitionManager::MxTransitionManager()
{
  m_animationTimer = 0;
  m_transitionType = NOT_TRANSITIONING;
  m_ddSurface = NULL;
  m_waitIndicator = NULL;
  m_copyBuffer = NULL;
  m_copyFlags.bit0 = FALSE;
  m_unk28.bit0 = FALSE;
  m_unk24 = 0;
}

// OFFSET: LEGO1 0x1004ba00
MxTransitionManager::~MxTransitionManager()
{
  free(m_copyBuffer);

  if (m_waitIndicator != NULL) {
    delete m_waitIndicator->GetAction();
    delete m_waitIndicator;
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
    // Generate the list of columns in order...
    for (MxS32 i = 0; i < 640; i++) {
      m_columnOrder[i] = i;
    }

    // ...then shuffle the list (to ensure that we hit each column once)
    for (i = 0; i < 640; i++) {
      MxS32 swap = rand() % 640;
      MxU16 t = m_columnOrder[i];
      m_columnOrder[i] = m_columnOrder[swap];
      m_columnOrder[swap] = t;
    }

    // For each scanline, pick a random X offset
    for (i = 0; i < 480; i++) {
      m_randomShift[i] = rand() % 640;
    }
  }

  // Run one tick of the animation
  DDSURFACEDESC ddsd;
  memset(&ddsd, 0, sizeof(ddsd));
  ddsd.dwSize = sizeof(ddsd);

  HRESULT res = m_ddSurface->Lock(NULL, &ddsd, 1, NULL);
  if (res == DDERR_SURFACELOST) {
    m_ddSurface->Restore();
    res = m_ddSurface->Lock(NULL, &ddsd, 1, NULL);
  }

  if (res == DD_OK) {
    SubmitCopyRect(ddsd);

    for (MxS32 i = 0; i < 640; i++) {
      // Select 16 columns on each tick
      if (m_animationTimer * 16 > m_columnOrder[i])
        continue;

      if (m_animationTimer * 16 + 15 < m_columnOrder[i])
        continue;

      for (MxS32 j = 0; j < 480; j++) {
        // Shift the chosen column a different amount at each scanline.
        // We use the same shift for that scanline each time.
        // By the end, every pixel gets hit.
        MxS32 ofs = (m_randomShift[j] + i) % 640;

        // Set the chosen pixel to black
        if (ddsd.ddpfPixelFormat.dwRGBBitCount == 8) {
          ((MxU8*)ddsd.lpSurface)[j * ddsd.lPitch + ofs] = 0;
        } else {
          ((MxU16*)ddsd.lpSurface)[j * ddsd.lPitch + ofs] = 0;
        }
      }
    }

    SetupCopyRect(ddsd);
    m_ddSurface->Unlock(ddsd.lpSurface);

    if (VideoManager()->GetVideoParam().flags().GetFlipSurfaces()) {
      LPDIRECTDRAWSURFACE surf = VideoManager()->GetDisplaySurface()->GetDirectDrawSurface1();
      surf->BltFast(NULL, NULL, m_ddSurface, &g_fullScreenRect, 0x10);
    }

    m_animationTimer++;
  }
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
                                              MxBool p_doCopy, MxBool p_playMusicInAnim)
{
  if (this->m_transitionType == NOT_TRANSITIONING) {
    if (!p_playMusicInAnim) {
      MxBackgroundAudioManager *backgroundAudioManager = BackgroundAudioManager();
      backgroundAudioManager->Stop();
    }

    this->m_transitionType = p_animationType;

    m_copyFlags.bit0 = p_doCopy;

    if (m_copyFlags.bit0 && m_waitIndicator != NULL) {
      m_waitIndicator->Enable(TRUE);

      MxDSAction *action = m_waitIndicator->GetAction();
      action->SetLoopCount(10000);
      action->SetFlags(action->GetFlags() | 0x200);
    }

    MxU32 time = timeGetTime();
    this->m_systemTime = time;

    this->m_animationSpeed = p_speed;

    MxTickleManager *tickleManager = TickleManager();
    tickleManager->RegisterClient(this, p_speed);

    LegoInputManager *inputManager = InputManager();
    inputManager->m_unk0x88 = TRUE;
    inputManager->m_unk0x336 = FALSE;

    LegoVideoManager *videoManager = VideoManager();
    videoManager->SetUnkE4(FALSE);

    SetAppCursor(1);
    return SUCCESS;
  }
  return FAILURE;
}

// OFFSET: LEGO1 0x1004c470 STUB
void MxTransitionManager::SetWaitIndicator(MxVideoPresenter *videoPresenter)
{
  // TODO
}

// OFFSET: LEGO1 0x1004c4d0
void MxTransitionManager::SubmitCopyRect(DDSURFACEDESC &ddsc)
{
  // Check if the copy rect is setup
  if (m_copyFlags.bit0 == FALSE || m_waitIndicator == NULL || m_copyBuffer == NULL) {
    return;
  }

  // Copy the copy rect onto the surface
  char *dst;

  DWORD bytesPerPixel = ddsc.ddpfPixelFormat.dwRGBBitCount / 8;

  const char *src = (const char *)m_copyBuffer;

  LONG copyPitch;
  copyPitch = ((m_copyRect.right - m_copyRect.left) + 1) * bytesPerPixel;

  LONG y;
  dst = (char *)ddsc.lpSurface + (ddsc.lPitch * m_copyRect.top) + (bytesPerPixel * m_copyRect.left);

  for (y = 0; y < m_copyRect.bottom - m_copyRect.top + 1; ++y) {
    memcpy(dst, src, copyPitch);
    src += copyPitch;
    dst += ddsc.lPitch;
  }

  // Free the copy buffer
  free(m_copyBuffer);
  m_copyBuffer = NULL;
}

// OFFSET: LEGO1 0x1004c580 STUB
void MxTransitionManager::SetupCopyRect(DDSURFACEDESC &ddsc)
{
  // TODO
}
