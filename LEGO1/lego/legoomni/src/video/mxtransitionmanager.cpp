#include "mxtransitionmanager.h"

#include "legoinputmanager.h"
#include "legoutil.h"
#include "legovideomanager.h"
#include "legoworld.h"
#include "mxbackgroundaudiomanager.h"
#include "mxparam.h"
#include "mxticklemanager.h"

DECOMP_SIZE_ASSERT(MxTransitionManager, 0x900);

// GLOBAL: LEGO1 0x100f4378
RECT g_fullScreenRect = {0, 0, 640, 480};

// FUNCTION: LEGO1 0x1004b8d0
MxTransitionManager::MxTransitionManager()
{
	m_animationTimer = 0;
	m_transitionType = e_notTransitioning;
	m_ddSurface = NULL;
	m_waitIndicator = NULL;
	m_copyBuffer = NULL;
	m_copyFlags.m_bit0 = FALSE;
	m_unk0x28.m_bit0 = FALSE;
	m_unk0x24 = 0;
}

// FUNCTION: LEGO1 0x1004ba00
MxTransitionManager::~MxTransitionManager()
{
	delete[] m_copyBuffer;

	if (m_waitIndicator != NULL) {
		delete m_waitIndicator->GetAction();
		delete m_waitIndicator;
	}

	TickleManager()->UnregisterClient(this);
}

// FUNCTION: LEGO1 0x1004baa0
MxResult MxTransitionManager::GetDDrawSurfaceFromVideoManager() // vtable+0x14
{
	LegoVideoManager* videoManager = VideoManager();
	this->m_ddSurface = videoManager->GetDisplaySurface()->GetDirectDrawSurface2();
	return SUCCESS;
}

// FUNCTION: LEGO1 0x1004bac0
MxResult MxTransitionManager::Tickle()
{
	if (this->m_animationSpeed + this->m_systemTime > timeGetTime()) {
		return SUCCESS;
	}

	this->m_systemTime = timeGetTime();

	switch (this->m_transitionType) {
	case e_noAnimation:
		TransitionNone();
		break;
	case e_dissolve:
		TransitionDissolve();
		break;
	case e_pixelation:
		TransitionPixelation();
		break;
	case e_screenWipe:
		TransitionWipe();
		break;
	case e_windows:
		TransitionWindows();
		break;
	case e_broken:
		TransitionBroken();
		break;
	}
	return SUCCESS;
}

// FUNCTION: LEGO1 0x1004bb70
MxResult MxTransitionManager::StartTransition(
	TransitionType p_animationType,
	MxS32 p_speed,
	MxBool p_doCopy,
	MxBool p_playMusicInAnim
)
{
	if (this->m_transitionType == e_notTransitioning) {
		if (!p_playMusicInAnim) {
			MxBackgroundAudioManager* backgroundAudioManager = BackgroundAudioManager();
			backgroundAudioManager->Stop();
		}

		this->m_transitionType = p_animationType;

		m_copyFlags.m_bit0 = p_doCopy;

		if (m_copyFlags.m_bit0 && m_waitIndicator != NULL) {
			m_waitIndicator->Enable(TRUE);

			MxDSAction* action = m_waitIndicator->GetAction();
			action->SetLoopCount(10000);
			action->SetFlags(action->GetFlags() | MxDSAction::c_bit10);
		}

		MxU32 time = timeGetTime();
		this->m_systemTime = time;

		this->m_animationSpeed = p_speed;

		MxTickleManager* tickleManager = TickleManager();
		tickleManager->RegisterClient(this, p_speed);

		LegoInputManager* inputManager = InputManager();
		inputManager->SetUnknown88(TRUE);
		inputManager->SetUnknown336(FALSE);

		LegoVideoManager* videoManager = VideoManager();
		videoManager->SetRender3D(FALSE);

		SetAppCursor(1);
		return SUCCESS;
	}
	return FAILURE;
}

// FUNCTION: LEGO1 0x1004bc30
void MxTransitionManager::EndTransition(MxBool p_notifyWorld)
{
	if (m_transitionType != e_notTransitioning) {
		m_transitionType = e_notTransitioning;

		m_copyFlags.m_bit0 = FALSE;

		TickleManager()->UnregisterClient(this);

		if (p_notifyWorld) {
			LegoWorld* world = CurrentWorld();

			if (world) {
#ifdef COMPAT_MODE
				{
					MxNotificationParam param(c_notificationTransitioned, this);
					world->Notify(param);
				}
#else
				world->Notify(MxNotificationParam(c_notificationTransitioned, this));
#endif
			}
		}
	}
}

// FUNCTION: LEGO1 0x1004bcf0
void MxTransitionManager::TransitionNone()
{
	LegoVideoManager* videoManager = VideoManager();
	videoManager->GetDisplaySurface()->ClearScreen();
	EndTransition(TRUE);
}

// FUNCTION: LEGO1 0x1004bd10
void MxTransitionManager::TransitionDissolve()
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
		MxS32 i;
		for (i = 0; i < 640; i++) {
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

	HRESULT res = m_ddSurface->Lock(NULL, &ddsd, DDLOCK_WAIT, NULL);
	if (res == DDERR_SURFACELOST) {
		m_ddSurface->Restore();
		res = m_ddSurface->Lock(NULL, &ddsd, DDLOCK_WAIT, NULL);
	}

	if (res == DD_OK) {
		SubmitCopyRect(&ddsd);

		for (MxS32 col = 0; col < 640; col++) {
			// Select 16 columns on each tick
			if (m_animationTimer * 16 > m_columnOrder[col]) {
				continue;
			}

			if (m_animationTimer * 16 + 15 < m_columnOrder[col]) {
				continue;
			}

			for (MxS32 row = 0; row < 480; row++) {
				// Shift the chosen column a different amount at each scanline.
				// We use the same shift for that scanline each time.
				// By the end, every pixel gets hit.
				MxS32 xShift = (m_randomShift[row] + col) % 640;

				// Set the chosen pixel to black
				if (ddsd.ddpfPixelFormat.dwRGBBitCount == 8) {
					MxU8* surf = (MxU8*) ddsd.lpSurface + ddsd.lPitch * row + xShift;
					*surf = 0;
				}
				else {
					MxU8* surf = (MxU8*) ddsd.lpSurface + ddsd.lPitch * row + xShift * 2;
					*(MxU16*) surf = 0;
				}
			}
		}

		SetupCopyRect(&ddsd);
		m_ddSurface->Unlock(ddsd.lpSurface);

		if (VideoManager()->GetVideoParam().Flags().GetFlipSurfaces()) {
			LPDIRECTDRAWSURFACE surf = VideoManager()->GetDisplaySurface()->GetDirectDrawSurface1();
			surf->BltFast(0, 0, m_ddSurface, &g_fullScreenRect, DDBLTFAST_WAIT);
		}

		m_animationTimer++;
	}
}

// FUNCTION: LEGO1 0x1004bed0
void MxTransitionManager::TransitionPixelation()
{
	if (m_animationTimer == 16) {
		m_animationTimer = 0;
		EndTransition(TRUE);
		return;
	}

	if (m_animationTimer == 0) {
		// Same init/shuffle steps as the dissolve transition, except that
		// we are using big blocky pixels and only need 64 columns.
		MxS32 i;
		for (i = 0; i < 64; i++) {
			m_columnOrder[i] = i;
		}

		for (i = 0; i < 64; i++) {
			MxS32 swap = rand() % 64;
			MxU16 t = m_columnOrder[i];
			m_columnOrder[i] = m_columnOrder[swap];
			m_columnOrder[swap] = t;
		}

		// The same is true here. We only need 48 rows.
		for (i = 0; i < 48; i++) {
			m_randomShift[i] = rand() % 64;
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

		for (MxS32 col = 0; col < 64; col++) {
			// Select 4 columns on each tick
			if (m_animationTimer * 4 > m_columnOrder[col]) {
				continue;
			}

			if (m_animationTimer * 4 + 3 < m_columnOrder[col]) {
				continue;
			}

			for (MxS32 row = 0; row < 48; row++) {
				// To do the pixelation, we subdivide the 640x480 surface into
				// 10x10 pixel blocks. At the chosen block, we sample the top-leftmost
				// color and set the other 99 pixels to that value.

				// First, get the offset of the 10x10 block that we will sample for this row.
				MxS32 xShift = 10 * ((m_randomShift[row] + col) % 64);

				// Combine xShift with this value to target the correct location in the buffer.
				MxS32 bytesPerPixel = ddsd.ddpfPixelFormat.dwRGBBitCount / 8;

				// Seek to the sample position.
				MxU8* source = (MxU8*) ddsd.lpSurface + 10 * row * ddsd.lPitch + bytesPerPixel * xShift;

				// Sample byte or word depending on display mode.
				MxU32 sample = bytesPerPixel == 1 ? *source : *(MxU16*) source;

				// For each of the 10 rows in the 10x10 square:
				for (MxS32 k = 10 * row; k < 10 * row + 10; k++) {
					if (ddsd.ddpfPixelFormat.dwRGBBitCount == 8) {
						MxU8* pos = (MxU8*) ddsd.lpSurface + k * ddsd.lPitch + xShift;

						for (MxS32 tt = 0; tt < 10; tt++) {
							pos[tt] = sample;
						}
					}
					else {
						// Need to double xShift because it measures pixels not bytes
						MxU16* pos = (MxU16*) ((MxU8*) ddsd.lpSurface + k * ddsd.lPitch + 2 * xShift);

						for (MxS32 tt = 0; tt < 10; tt++) {
							pos[tt] = sample;
						}
					}
				}
			}
		}

		SetupCopyRect(&ddsd);
		m_ddSurface->Unlock(ddsd.lpSurface);

		if (VideoManager()->GetVideoParam().Flags().GetFlipSurfaces()) {
			LPDIRECTDRAWSURFACE surf = VideoManager()->GetDisplaySurface()->GetDirectDrawSurface1();
			surf->BltFast(0, 0, m_ddSurface, &g_fullScreenRect, DDBLTFAST_WAIT);
		}

		m_animationTimer++;
	}
}

// FUNCTION: LEGO1 0x1004c170
void MxTransitionManager::TransitionWipe()
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

	HRESULT res = m_ddSurface->Lock(NULL, &ddsd, DDLOCK_WAIT, NULL);
	if (res == DDERR_SURFACELOST) {
		m_ddSurface->Restore();
		res = m_ddSurface->Lock(NULL, &ddsd, DDLOCK_WAIT, NULL);
	}

	if (res == DD_OK) {
		SubmitCopyRect(&ddsd);

		// For each of the 240 animation ticks, blank out two scanlines
		// starting at the top of the screen.
		// (dwRGBBitCount / 8) will tell how many bytes are used per pixel.
		MxU8* line = (MxU8*) ddsd.lpSurface + 2 * ddsd.lPitch * m_animationTimer;
		memset(line, 0, 640 * ddsd.ddpfPixelFormat.dwRGBBitCount / 8);

		line += ddsd.lPitch;
		memset(line, 0, 640 * ddsd.ddpfPixelFormat.dwRGBBitCount / 8);

		SetupCopyRect(&ddsd);
		m_ddSurface->Unlock(ddsd.lpSurface);

		m_animationTimer++;
	}
}

// FUNCTION: LEGO1 0x1004c270
void MxTransitionManager::TransitionWindows()
{
	if (m_animationTimer == 240) {
		m_animationTimer = 0;
		EndTransition(TRUE);
		return;
	}

	DDSURFACEDESC ddsd;
	memset(&ddsd, 0, sizeof(ddsd));
	ddsd.dwSize = sizeof(ddsd);

	HRESULT res = m_ddSurface->Lock(NULL, &ddsd, DDLOCK_WAIT, NULL);
	if (res == DDERR_SURFACELOST) {
		m_ddSurface->Restore();
		res = m_ddSurface->Lock(NULL, &ddsd, DDLOCK_WAIT, NULL);
	}

	if (res == DD_OK) {
		SubmitCopyRect(&ddsd);

		MxU8* line = (MxU8*) ddsd.lpSurface + m_animationTimer * ddsd.lPitch;

		MxS32 bytesPerPixel = ddsd.ddpfPixelFormat.dwRGBBitCount / 8;
		MxS32 bytesPerLine = bytesPerPixel * 640;

		memset(line, 0, bytesPerLine);

		for (MxS32 i = m_animationTimer + 1; i < 480 - m_animationTimer; i++) {
			line += ddsd.lPitch;

			memset(line + m_animationTimer * bytesPerPixel, 0, bytesPerPixel);
			memset(line + 640 + (-1 - m_animationTimer) * bytesPerPixel, 0, bytesPerPixel);
		}

		line += ddsd.lPitch;
		memset(line, 0, bytesPerLine);

		SetupCopyRect(&ddsd);
		m_ddSurface->Unlock(ddsd.lpSurface);

		m_animationTimer++;
	}
}

// FUNCTION: LEGO1 0x1004c3e0
void MxTransitionManager::TransitionBroken()
{
	// This function has no actual animation logic.
	// It also never calls EndTransition to
	// properly terminate the transition, so
	// the game just hangs forever.

	DDSURFACEDESC ddsd;
	memset(&ddsd, 0, sizeof(ddsd));
	ddsd.dwSize = sizeof(ddsd);

	HRESULT res = m_ddSurface->Lock(NULL, &ddsd, DDLOCK_WAIT, NULL);
	if (res == DDERR_SURFACELOST) {
		m_ddSurface->Restore();
		res = m_ddSurface->Lock(NULL, &ddsd, DDLOCK_WAIT, NULL);
	}

	if (res == DD_OK) {
		SubmitCopyRect(&ddsd);
		SetupCopyRect(&ddsd);
		m_ddSurface->Unlock(ddsd.lpSurface);
	}
}

// FUNCTION: LEGO1 0x1004c470
void MxTransitionManager::SetWaitIndicator(MxVideoPresenter* p_waitIndicator)
{
	// End current wait indicator
	if (m_waitIndicator != NULL) {
		m_waitIndicator->GetAction()->SetFlags(m_waitIndicator->GetAction()->GetFlags() & ~MxDSAction::c_world);
		m_waitIndicator->EndAction();
		m_waitIndicator = NULL;
	}

	// Check if we were given a new wait indicator
	if (p_waitIndicator != NULL) {
		// Setup the new wait indicator
		m_waitIndicator = p_waitIndicator;

		LegoVideoManager* videoManager = VideoManager();
		videoManager->UnregisterPresenter(*m_waitIndicator);

		if (m_waitIndicator->GetCurrentTickleState() < MxPresenter::e_streaming) {
			m_waitIndicator->Tickle();
		}
	}
	else {
		// Disable copy rect
		m_copyFlags.m_bit0 = FALSE;
	}
}

// FUNCTION: LEGO1 0x1004c4d0
void MxTransitionManager::SubmitCopyRect(LPDDSURFACEDESC p_ddsc)
{
	// Check if the copy rect is setup
	if (m_copyFlags.m_bit0 == FALSE || m_waitIndicator == NULL || m_copyBuffer == NULL) {
		return;
	}

	// Copy the copy rect onto the surface
	MxU8* dst;

	MxU32 bytesPerPixel = p_ddsc->ddpfPixelFormat.dwRGBBitCount / 8;

	const MxU8* src = (const MxU8*) m_copyBuffer;

	MxS32 copyPitch;
	copyPitch = ((m_copyRect.right - m_copyRect.left) + 1) * bytesPerPixel;

	MxS32 y;
	dst = (MxU8*) p_ddsc->lpSurface + (p_ddsc->lPitch * m_copyRect.top) + (bytesPerPixel * m_copyRect.left);

	for (y = 0; y < m_copyRect.bottom - m_copyRect.top + 1; ++y) {
		memcpy(dst, src, copyPitch);
		src += copyPitch;
		dst += p_ddsc->lPitch;
	}

	// Free the copy buffer
	delete[] m_copyBuffer;
	m_copyBuffer = NULL;
}

// FUNCTION: LEGO1 0x1004c580
void MxTransitionManager::SetupCopyRect(LPDDSURFACEDESC p_ddsc)
{
	// Check if the copy rect is setup
	if (m_copyFlags.m_bit0 == FALSE || m_waitIndicator == NULL) {
		return;
	}

	// Tickle wait indicator
	m_waitIndicator->Tickle();

	// Check if wait indicator has started
	if (m_waitIndicator->GetCurrentTickleState() >= MxPresenter::e_streaming) {
		// Setup the copy rect
		MxU32 copyPitch = (p_ddsc->ddpfPixelFormat.dwRGBBitCount / 8) *
						  (m_copyRect.right - m_copyRect.left + 1); // This uses m_copyRect, seemingly erroneously
		MxU32 bytesPerPixel = p_ddsc->ddpfPixelFormat.dwRGBBitCount / 8;

		m_copyRect.left = m_waitIndicator->GetLocation().GetX();
		m_copyRect.top = m_waitIndicator->GetLocation().GetY();

		MxS32 height = m_waitIndicator->GetHeight();
		MxS32 width = m_waitIndicator->GetWidth();

		m_copyRect.right = m_copyRect.left + width - 1;
		m_copyRect.bottom = m_copyRect.top + height - 1;

		// Allocate the copy buffer
		const MxU8* src =
			(const MxU8*) p_ddsc->lpSurface + m_copyRect.top * p_ddsc->lPitch + bytesPerPixel * m_copyRect.left;

		m_copyBuffer = new MxU8[bytesPerPixel * width * height];
		if (!m_copyBuffer) {
			return;
		}

		// Copy into the copy buffer
		MxU8* dst = m_copyBuffer;

		for (MxS32 i = 0; i < (m_copyRect.bottom - m_copyRect.top + 1); i++) {
			memcpy(dst, src, copyPitch);
			src += p_ddsc->lPitch;
			dst += copyPitch;
		}
	}

	// Setup display surface
	if ((m_waitIndicator->GetAction()->GetFlags() & MxDSAction::c_bit5) != 0) {
		MxDisplaySurface* displaySurface = VideoManager()->GetDisplaySurface();
		MxBool und = FALSE;
		displaySurface->VTable0x2c(
			p_ddsc,
			m_waitIndicator->GetBitmap(),
			0,
			0,
			m_waitIndicator->GetLocation().GetX(),
			m_waitIndicator->GetLocation().GetY(),
			m_waitIndicator->GetWidth(),
			m_waitIndicator->GetHeight(),
			und
		);
	}
	else {
		MxDisplaySurface* displaySurface = VideoManager()->GetDisplaySurface();
		displaySurface->VTable0x24(
			p_ddsc,
			m_waitIndicator->GetBitmap(),
			0,
			0,
			m_waitIndicator->GetLocation().GetX(),
			m_waitIndicator->GetLocation().GetY(),
			m_waitIndicator->GetWidth(),
			m_waitIndicator->GetHeight()
		);
	}
}
