#include "mxvideomanager.h"

#include "legoomni.h"
#include "mxautolocker.h"
#include "mxpresenter.h"
#include "mxticklemanager.h"

DECOMP_SIZE_ASSERT(MxVideoManager, 0x64)

// FUNCTION: LEGO1 0x100be1f0
MxVideoManager::MxVideoManager()
{
	Init();
}

// FUNCTION: LEGO1 0x100be270
void MxVideoManager::VTable0x34(MxU32 p_x, MxU32 p_y, MxU32 p_width, MxU32 p_height)
{
}

// FUNCTION: LEGO1 0x100be2a0
MxVideoManager::~MxVideoManager()
{
	Destroy(TRUE);
}

// FUNCTION: LEGO1 0x100be320
MxResult MxVideoManager::Init()
{
	this->m_pDirectDraw = NULL;
	this->m_pDirect3D = NULL;
	this->m_displaySurface = NULL;
	this->m_region = NULL;
	this->m_videoParam.SetPalette(NULL);
	this->m_unk0x60 = FALSE;
	return SUCCESS;
}

// FUNCTION: LEGO1 0x100be340
void MxVideoManager::Destroy(MxBool p_fromDestructor)
{
	if (m_thread) {
		m_thread->Terminate();
		delete m_thread;
	}
	else
		TickleManager()->UnregisterClient(this);

	m_criticalSection.Enter();

	if (m_displaySurface)
		delete m_displaySurface;

	if (m_region)
		delete m_region;

	if (m_videoParam.GetPalette())
		delete m_videoParam.GetPalette();

	if (m_unk0x60) {
		if (m_pDirectDraw)
			m_pDirectDraw->Release();
		if (m_pDirect3D)
			m_pDirect3D->Release();
	}

	Init();
	m_criticalSection.Leave();

	if (!p_fromDestructor)
		MxMediaManager::Destroy();
}

// FUNCTION: LEGO1 0x100be3e0
void MxVideoManager::UpdateRegion()
{
	if (m_region->VTable0x20() == FALSE) {
		MxRect32 rect(m_region->GetRect());
		rect.Intersect(m_videoParam.GetRect());

		m_displaySurface
			->Display(rect.GetLeft(), rect.GetTop(), rect.GetLeft(), rect.GetTop(), rect.GetWidth(), rect.GetHeight());
	}
}

// FUNCTION: LEGO1 0x100be440
void MxVideoManager::SortPresenterList()
{
	if (this->m_presenters->GetCount() <= 1)
		return;

	MxPresenterListCursor a(this->m_presenters);
	MxPresenterListCursor b(this->m_presenters);
	MxU32 count = this->m_presenters->GetCount() - 1;
	MxBool finished;

	if (count != 0) {
		do {
			a.Reset();
			b.Head();

			finished = TRUE;
			for (MxU32 i = count; i != 0; i--) {
				MxPresenter *presenterA, *presenterB;

				a.Next(presenterA);
				b.Next(presenterB);

				if (presenterA->GetDisplayZ() < presenterB->GetDisplayZ()) {
					a.SetValue(presenterB);
					b.SetValue(presenterA);
					finished = FALSE;
				}
			}
		} while (!finished && --count != 0);
	}
}

// FUNCTION: LEGO1 0x100be600
MxResult MxVideoManager::VTable0x28(
	MxVideoParam& p_videoParam,
	LPDIRECTDRAW p_pDirectDraw,
	LPDIRECT3D p_pDirect3D,
	LPDIRECTDRAWSURFACE p_ddSurface1,
	LPDIRECTDRAWSURFACE p_ddSurface2,
	LPDIRECTDRAWCLIPPER p_ddClipper,
	MxU32 p_frequencyMS,
	MxBool p_createThread
)
{
	MxBool locked = FALSE;
	MxResult status = FAILURE;

	m_unk0x60 = FALSE;

	if (MxMediaManager::InitPresenters() != SUCCESS)
		goto done;

	m_criticalSection.Enter();
	locked = TRUE;

	m_videoParam = p_videoParam;
	m_region = new MxRegion();

	if (!m_region)
		goto done;

	m_pDirectDraw = p_pDirectDraw;
	m_pDirect3D = p_pDirect3D;

	MxPalette* palette;
	if (p_videoParam.GetPalette() == NULL) {
		palette = new MxPalette();
		m_videoParam.SetPalette(palette);

		if (!palette)
			goto done;
	}
	else {
		palette = p_videoParam.GetPalette()->Clone();
		m_videoParam.SetPalette(palette);

		if (!palette)
			goto done;
	}

	m_displaySurface = new MxDisplaySurface();
	if (m_displaySurface && m_displaySurface->Init(m_videoParam, p_ddSurface1, p_ddSurface2, p_ddClipper) == SUCCESS) {
		m_displaySurface->SetPalette(m_videoParam.GetPalette());

		if (p_createThread) {
			m_thread = new MxTickleThread(this, p_frequencyMS);

			if (!m_thread || m_thread->Start(0, 0) != SUCCESS)
				goto done;
		}
		else
			TickleManager()->RegisterClient(this, p_frequencyMS);

		status = SUCCESS;
	}

done:
	if (status != SUCCESS)
		Destroy();

	if (locked)
		m_criticalSection.Leave();

	return status;
}

// FUNCTION: LEGO1 0x100be820
MxResult MxVideoManager::Create(MxVideoParam& p_videoParam, MxU32 p_frequencyMS, MxBool p_createThread)
{
	MxBool locked = FALSE;
	MxResult status = FAILURE;

	m_unk0x60 = TRUE;

	if (MxMediaManager::InitPresenters() != SUCCESS)
		goto done;

	m_criticalSection.Enter();
	locked = TRUE;

	m_videoParam = p_videoParam;
	m_region = new MxRegion();

	if (!m_region)
		goto done;

	if (DirectDrawCreate(NULL, &m_pDirectDraw, NULL) != DD_OK)
		goto done;

	if (m_pDirectDraw->SetCooperativeLevel(MxOmni::GetInstance()->GetWindowHandle(), DDSCL_NORMAL) != DD_OK)
		goto done;

	MxPalette* palette;
	if (p_videoParam.GetPalette() == NULL) {
		palette = new MxPalette();
		m_videoParam.SetPalette(palette);

		if (!palette)
			goto done;
	}
	else {
		palette = p_videoParam.GetPalette()->Clone();
		m_videoParam.SetPalette(palette);

		if (!palette)
			goto done;
	}

	m_displaySurface = new MxDisplaySurface();
	if (m_displaySurface && m_displaySurface->Create(m_videoParam) == SUCCESS) {
		m_displaySurface->SetPalette(m_videoParam.GetPalette());

		if (p_createThread) {
			m_thread = new MxTickleThread(this, p_frequencyMS);

			if (!m_thread || m_thread->Start(0, 0) != SUCCESS)
				goto done;
		}
		else
			TickleManager()->RegisterClient(this, p_frequencyMS);

		status = SUCCESS;
	}

done:
	if (status != SUCCESS)
		Destroy();

	if (locked)
		m_criticalSection.Leave();

	return status;
}

// FUNCTION: LEGO1 0x100bea50
void MxVideoManager::Destroy()
{
	Destroy(FALSE);
}

// FUNCTION: LEGO1 0x100bea60
void MxVideoManager::InvalidateRect(MxRect32& p_rect)
{
	m_criticalSection.Enter();

	if (m_region)
		m_region->VTable0x18(p_rect);

	m_criticalSection.Leave();
}

// FUNCTION: LEGO1 0x100bea90
MxResult MxVideoManager::Tickle()
{
	MxAutoLocker lock(&this->m_criticalSection);

	SortPresenterList();

	MxPresenter* presenter;
	MxPresenterListCursor cursor(this->m_presenters);

	while (cursor.Next(presenter))
		presenter->Tickle();

	cursor.Reset();

	while (cursor.Next(presenter))
		presenter->PutData();

	UpdateRegion();
	m_region->Reset();

	return SUCCESS;
}

// FUNCTION: LEGO1 0x100bebe0
MxResult MxVideoManager::RealizePalette(MxPalette* p_palette)
{
	PALETTEENTRY paletteEntries[256];

	this->m_criticalSection.Enter();

	if (p_palette && this->m_videoParam.GetPalette()) {
		p_palette->GetEntries(paletteEntries);
		this->m_videoParam.GetPalette()->SetEntries(paletteEntries);
		this->m_displaySurface->SetPalette(this->m_videoParam.GetPalette());
	}

	this->m_criticalSection.Leave();
	return SUCCESS;
}
