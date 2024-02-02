// TglSurface.cpp : implementation file

#include "tglsurface.h"

#include "decomp.h"

DECOMP_SIZE_ASSERT(TglSurface, 0x70);

using namespace Tgl;

/////////////////////////////////////////////////////////////////////////////
// TglSurface

// FUNCTION: LEGO1 0x100abbf0
TglSurface::TglSurface()
{
	m_pRenderer = 0;
	m_pDevice = 0;
	m_pView = 0;
	m_pScene = 0;

	m_width = 0;
	m_height = 0;

	m_stopRendering = FALSE;
	m_isInitialized = FALSE;

	// statistics
	m_frameCount = 0;
#ifdef _DEBUG
	m_triangleCount = 0;
#endif
}

// FUNCTION: LEGO1 0x100abd60
TglSurface::~TglSurface()
{
	Destroy();
}

// FUNCTION: LEGO1 0x100abde0
void TglSurface::Destroy()
{
	DestroyView();

	delete m_pDevice;
	m_pDevice = 0;

	m_pRenderer = 0;
	m_pScene = 0;
}

// ???
// FUNCTION: LEGO1 0x100abe10
int GetBitsPerPixel(IDirectDrawSurface* pSurface)
{
	DDPIXELFORMAT pixelFormat;
	HRESULT result;

	memset(&pixelFormat, 0, sizeof(pixelFormat));
	pixelFormat.dwSize = sizeof(pixelFormat);

	result = pSurface->GetPixelFormat(&pixelFormat);
	assert(result == DD_OK);
	assert(pixelFormat.dwFlags & DDPF_RGB);

	return pixelFormat.dwRGBBitCount;
}

// FUNCTION: LEGO1 0x100abe50
BOOL TglSurface::Create(const CreateStruct& rCreateStruct, Renderer* pRenderer, Group* pScene)
{
	DeviceDirect3DCreateData createData = {rCreateStruct.m_direct3d, rCreateStruct.m_d3dDevice};
	int bitsPerPixel = GetBitsPerPixel(rCreateStruct.m_pFrontBuffer);

	ColorModel colorModel = Ramp;
	ShadingModel shadingModel = Gouraud;
	int shadeCount = 32;
	BOOL dither = TRUE;
	int textureShadeCount = -1;
	int textureColorCount = -1;
	Result result;

	m_pRenderer = pRenderer;
	m_pScene = pScene;
	m_pDevice = m_pRenderer->CreateDevice(createData);

	if (!m_pDevice) {
		assert(0);
		m_pRenderer = 0;
		m_pScene = 0;
		return FALSE;
	}

	if (bitsPerPixel == 1) {
		shadeCount = 4;
		textureShadeCount = 4;
	}
	else if (bitsPerPixel == 8) {
		shadeCount = 16;
		dither = FALSE;
		textureShadeCount = 16;
		textureColorCount = 256;
	}
	else if (bitsPerPixel == 16) {
		shadeCount = 32;
		dither = FALSE;
		textureShadeCount = 32;
		textureColorCount = 256;
	}
	else if (bitsPerPixel >= 24) {
		shadeCount = 256;
		dither = FALSE;
		textureShadeCount = 256;
		textureColorCount = 64;
	}
	else {
		dither = FALSE;
	}

	if (textureShadeCount != -1) {
		result = pRenderer->SetTextureDefaultShadeCount(textureShadeCount);
		assert(Succeeded(result));
	}
	if (textureColorCount != -1) {
		result = pRenderer->SetTextureDefaultColorCount(textureColorCount);
		assert(Succeeded(result));
	}

	result = m_pDevice->SetColorModel(colorModel);
	assert(Succeeded(result));
	result = m_pDevice->SetShadingModel(shadingModel);
	assert(Succeeded(result));
	result = m_pDevice->SetShadeCount(shadeCount);
	assert(Succeeded(result));
	result = m_pDevice->SetDither(dither);
	assert(Succeeded(result));

	m_width = m_pDevice->GetWidth();
	m_height = m_pDevice->GetHeight();

	m_pView = CreateView(m_pRenderer, m_pDevice);
	if (!m_pView) {
		delete m_pDevice;
		m_pDevice = 0;
		m_pRenderer = 0;
		m_pScene = 0;
		return FALSE;
	}

	m_frameRateMeter.Reset();
	m_renderingRateMeter.Reset();
#ifdef _DEBUG
	m_triangleRateMeter.Reset();
#endif
	m_frameRateMeter.StartOperation();

	m_isInitialized = TRUE;

	return TRUE;
}

// FUNCTION: LEGO1 0x100ac030
void TglSurface::DestroyView()
{
	delete m_pView;
	m_pView = 0;
}

// FUNCTION: LEGO1 0x100ac050
double TglSurface::Render()
{
	MxStopWatch renderTimer;

	if (m_isInitialized && !m_stopRendering) {
		Result result;

#ifdef _DEBUG
		m_triangleRateMeter.StartOperation();
#endif
		m_renderingRateMeter.StartOperation();
		renderTimer.Start();

		// TODO: Wrong interface
		result = m_pView->Render((Tgl::Light*) m_pScene);

		renderTimer.Stop();
		assert(Succeeded(result));
		m_renderingRateMeter.EndOperation();
#ifdef _DEBUG
		m_triangleRateMeter.EndOperation();
#endif
		m_frameRateMeter.EndOperation();
		m_frameCount++;

#ifdef _DEBUG
		{
#if 0
			// FIXME: Tgl::Device::GetDrawnTriangleCount does not exist
			unsigned long triangleCount = m_pDevice->GetDrawnTriangleCount();
#else
			unsigned long triangleCount = 0;
#endif

			m_triangleRateMeter.IncreaseOperationCount(triangleCount - m_triangleCount - 1);
			m_triangleCount = triangleCount;
		}
#endif

#if 0
        // reset rate meters every 20 frames
        if ((++m_frameCount % 20) == 0)
#else
		// reset rate meters every 4 seconds
		if (m_frameRateMeter.ElapsedSeconds() > 4.0)
#endif
		{
			m_frameRateMeter.Reset();
			m_renderingRateMeter.Reset();
#ifdef _DEBUG
			m_triangleRateMeter.Reset();
#endif
		}

		m_frameRateMeter.StartOperation();
	}

	return renderTimer.ElapsedSeconds();
}
