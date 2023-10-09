#include "mxtransitionmanager.h"

#include "legovideomanager.h"
#include "legoinputmanager.h"
#include "legoutil.h"
#include "legoworld.h"
#include "mxbackgroundaudiomanager.h"
#include "mxparam.h"
#include "mxticklemanager.h"

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
  delete[] m_copyBuffer;

  if (m_waitIndicator != NULL) {
    delete m_waitIndicator->GetAction();
    delete m_waitIndicator;
  }

  TickleManager()->UnregisterClient(this);
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
      Transition_None();
      break;
    case DISSOLVE:
      Transition_Dissolve();
      break;
    case PIXELATION:
      Transition_Pixelation();
      break;
    case SCREEN_WIPE:
      Transition_Wipe();
      break;
    case WINDOWS:
      Transition_Windows();
      break;
    case BROKEN:
      Transition_Broken();
      break;
  }
  return SUCCESS;
}

// OFFSET: LEGO1 0x1004bc30
void MxTransitionManager::EndTransition(MxBool p_notifyWorld)
{
  if (m_transitionType != NOT_TRANSITIONING) {
    m_transitionType = NOT_TRANSITIONING;

    m_copyFlags.bit0 = FALSE;

    TickleManager()->UnregisterClient(this);

    if (p_notifyWorld) {
      LegoWorld *world = GetCurrentWorld();

      if (world) {
        world->Notify(MxNotificationParam(MXTRANSITIONMANAGER_TRANSITIONENDED, this));
      }
    }
  }
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
    SubmitCopyRect(&ddsd);

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

    SetupCopyRect(&ddsd);
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
      action->SetFlags(action->GetFlags() | MxDSAction::Flag_Bit9);
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

// OFFSET: LEGO1 0x1004bcf0
void MxTransitionManager::Transition_None()
{
  LegoVideoManager *videoManager = VideoManager();
  videoManager->GetDisplaySurface()->FUN_100ba640();
  EndTransition(TRUE);
}

// OFFSET: LEGO1 0x1004bed0 STUB
void MxTransitionManager::Transition_Pixelation()
{
  // TODO
}


// OFFSET: LEGO1 0x1004c270 STUB
void MxTransitionManager::Transition_Windows()
{
  // TODO
}

// OFFSET: LEGO1 0x1004c3e0 STUB
void MxTransitionManager::Transition_Broken()
{
  // TODO
}

// OFFSET: LEGO1 0x1004c170
void MxTransitionManager::Transition_Wipe()
{
  // If the animation is finished
  if (m_animationTimer == 240) {
    m_animationTimer = 0;
    EndTransition(TRUE);
    return;
  }

  DDSURFACEDESC ddsd;
  memset(&ddsd, 0, sizeof(ddsd));
  ddsd.dwSize = sizeof(ddsd);

  HRESULT res = m_ddSurface->Lock(NULL, &ddsd, 1, NULL);
  if (res == DDERR_SURFACELOST) {
    m_ddSurface->Restore();
    res = m_ddSurface->Lock(NULL, &ddsd, 1, NULL);
  }

  if (res == DD_OK) {
    SubmitCopyRect(&ddsd);

    // For each of the 240 animation ticks, blank out two scanlines
    // starting at the top of the screen.
    // (dwRGBBitCount / 8) will tell how many bytes are used per pixel.
    MxU8 *line = (MxU8*)ddsd.lpSurface + 2*ddsd.lPitch*m_animationTimer;
    memset(line, 0, 640 * ddsd.ddpfPixelFormat.dwRGBBitCount / 8);

    line += ddsd.lPitch;
    memset(line, 0, 640 * ddsd.ddpfPixelFormat.dwRGBBitCount / 8);

    SetupCopyRect(&ddsd);
    m_ddSurface->Unlock(ddsd.lpSurface);

    m_animationTimer++;
  }
}

// OFFSET: LEGO1 0x1004c470
void MxTransitionManager::SetWaitIndicator(MxVideoPresenter *p_waitIndicator)
{
  // End current wait indicator
  if (m_waitIndicator != NULL) {
    m_waitIndicator->GetAction()->SetFlags(m_waitIndicator->GetAction()->GetFlags() & ~MxDSAction::Flag_Parsed);
    m_waitIndicator->EndAction();
    m_waitIndicator = NULL;
  }

  // Check if we were given a new wait indicator
  if (p_waitIndicator != NULL) {
    // Setup the new wait indicator
    m_waitIndicator = p_waitIndicator;

    LegoVideoManager *videoManager = VideoManager();
    videoManager->RemovePresenter(*m_waitIndicator);

    if (m_waitIndicator->GetCurrentTickleState() < MxPresenter::TickleState_Streaming) {
      m_waitIndicator->Tickle();
    }
  } else {
    // Disable copy rect
    m_copyFlags.bit0 = FALSE;
  }
}

// OFFSET: LEGO1 0x1004c4d0
void MxTransitionManager::SubmitCopyRect(LPDDSURFACEDESC ddsc)
{
  // Check if the copy rect is setup
  if (m_copyFlags.bit0 == FALSE || m_waitIndicator == NULL || m_copyBuffer == NULL) {
    return;
  }

  // Copy the copy rect onto the surface
  MxU8 *dst;

  MxU32 bytesPerPixel = ddsc->ddpfPixelFormat.dwRGBBitCount / 8;

  const MxU8 *src = (const MxU8 *)m_copyBuffer;

  MxS32 copyPitch;
  copyPitch = ((m_copyRect.right - m_copyRect.left) + 1) * bytesPerPixel;

  MxS32 y;
  dst = (MxU8 *)ddsc->lpSurface + (ddsc->lPitch * m_copyRect.top) + (bytesPerPixel * m_copyRect.left);

  for (y = 0; y < m_copyRect.bottom - m_copyRect.top + 1; ++y) {
    memcpy(dst, src, copyPitch);
    src += copyPitch;
    dst += ddsc->lPitch;
  }

  // Free the copy buffer
  delete[] m_copyBuffer;
  m_copyBuffer = NULL;
}

// OFFSET: LEGO1 0x1004c580
void MxTransitionManager::SetupCopyRect(LPDDSURFACEDESC ddsc)
{
  // Check if the copy rect is setup
  if (m_copyFlags.bit0 == FALSE || m_waitIndicator == NULL) {
    return;
  }

  // Tickle wait indicator
  m_waitIndicator->Tickle();

  // Check if wait indicator has started
  if (m_waitIndicator->GetCurrentTickleState() >= MxPresenter::TickleState_Streaming) {
    // Setup the copy rect
    MxU32 copyPitch = (ddsc->ddpfPixelFormat.dwRGBBitCount / 8) * (m_copyRect.right - m_copyRect.left + 1); // This uses m_copyRect, seemingly erroneously
    MxU32 bytesPerPixel = ddsc->ddpfPixelFormat.dwRGBBitCount / 8;

    m_copyRect.left = m_waitIndicator->GetLocationX();
    m_copyRect.top = m_waitIndicator->GetLocationY();

    MxS32 height = m_waitIndicator->GetHeight();
    MxS32 width = m_waitIndicator->GetWidth();

    m_copyRect.right = m_copyRect.left + width - 1;
    m_copyRect.bottom = m_copyRect.top + height - 1;

    // Allocate the copy buffer
    const MxU8 *src = (const MxU8*)ddsc->lpSurface + m_copyRect.top * ddsc->lPitch + bytesPerPixel * m_copyRect.left;

    m_copyBuffer = new MxU8[bytesPerPixel * width * height];
    if (!m_copyBuffer)
      return;

    // Copy into the copy buffer
    MxU8 *dst = m_copyBuffer;

    for (MxS32 i = 0; i < (m_copyRect.bottom - m_copyRect.top + 1); i++)
    {
      memcpy(dst, src, copyPitch);
      src += ddsc->lPitch;
      dst += copyPitch;
    }
  }

  // Setup display surface
  if ((m_waitIndicator->GetAction()->GetFlags() & MxDSAction::Flag_Bit5) != 0)
  {
    MxDisplaySurface *displaySurface = VideoManager()->GetDisplaySurface();
    MxBool unkbool = FALSE;
    displaySurface->vtable2c(ddsc, m_waitIndicator->m_bitmap, 0, 0, m_waitIndicator->GetLocationX(), m_waitIndicator->GetLocationY(), m_waitIndicator->GetWidth(), m_waitIndicator->GetHeight(), unkbool);
  }
  else
  {
    MxDisplaySurface *displaySurface = VideoManager()->GetDisplaySurface();
    displaySurface->vtable24(ddsc, m_waitIndicator->m_bitmap, 0, 0, m_waitIndicator->GetLocationX(), m_waitIndicator->GetLocationY(), m_waitIndicator->GetWidth(), m_waitIndicator->GetHeight());
  }
}
