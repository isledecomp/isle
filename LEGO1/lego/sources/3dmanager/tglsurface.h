#ifndef _TglSurface_h
#define _TglSurface_h

#include "mxdirectx/mxstopwatch.h"
#include "tgl/tgl.h"

namespace Tgl
{
class Renderer;
class Device;
class View;
class Group;
} // namespace Tgl

/////////////////////////////////////////////////////////////////////////////
// TglSurface

// VTABLE: LEGO1 0x100dc060
// SIZE 0x70
class TglSurface {
public:
	// SIZE 0x28
	struct CreateStruct {
		const GUID* m_pDriverGUID;          // 0x00
		HWND m_hWnd;                        // 0x04
		IDirectDraw* m_pDirectDraw;         // 0x08
		IDirectDrawSurface* m_pFrontBuffer; // 0x0c
		IDirectDrawSurface* m_pBackBuffer;  // 0x10
		IDirectDrawPalette* m_pPalette;     // 0x14
		BOOL m_isFullScreen;                // 0x18
		BOOL m_isWideViewAngle;             // 0x1c
		IDirect3D2* m_direct3d;             // 0x20
		IDirect3DDevice2* m_d3dDevice;      // 0x24
	};

public:
	TglSurface();
	virtual ~TglSurface();

	virtual BOOL Create(const CreateStruct&, Tgl::Renderer*, Tgl::Group* pScene); // vtable+0x04
	virtual void Destroy();                                                       // vtable+0x08
	virtual double Render(); // render time in seconds // vtable+0x0c

	Tgl::Renderer* GetRenderer() const { return m_pRenderer; }
	Tgl::Device* GetDevice() const { return m_pDevice; }
	Tgl::View* GetView() const { return m_pView; }
	Tgl::Group* GetScene() const { return m_pScene; }

	unsigned long GetWidth() const { return m_width; }
	unsigned long GetHeight() const { return m_height; }

	double GetRenderingRate() const { return m_renderingRateMeter.Frequency(); }
	double GetFrameRate() const { return m_frameRateMeter.Frequency(); }
	unsigned long GetFrameCount() const { return m_frameCount; }
#ifdef _DEBUG
	double GetTriangleRate() const { return m_triangleRateMeter.Frequency(); }
#endif

protected:
	virtual Tgl::View* CreateView(Tgl::Renderer*, Tgl::Device*) = 0; // vtable+0x10
	virtual void DestroyView();                                      // vtable+0x14

private:
	Tgl::Renderer* m_pRenderer; // 0x08
	Tgl::Device* m_pDevice;     // 0x0c
	Tgl::View* m_pView;         // 0x10
	Tgl::Group* m_pScene;       // 0x14

	unsigned long m_width;  // 0x18
	unsigned long m_height; // 0x1c

	BOOL m_isInitialized; // 0x20
	BOOL m_stopRendering; // 0x24

	// statistics
	MxFrequencyMeter m_renderingRateMeter; // 0x28
	MxFrequencyMeter m_frameRateMeter;     // 0x48
	unsigned long m_frameCount;            // 0x68
#ifdef _DEBUG
	MxFrequencyMeter m_triangleRateMeter;
	unsigned long m_triangleCount;
#endif
};

/////////////////////////////////////////////////////////////////////////////

// SYNTHETIC: LEGO1 0x100abcf0
// TglSurface::`scalar deleting destructor'

#endif /* _TglSurface_h */
