#ifndef _Lego3DManager_h
#define _Lego3DManager_h

#include "assert.h"
#include "lego3dview.h"

class Tgl::Renderer;
class Tgl::Group;
class ViewROI;

// ??? for now
class ViewLODListManager;

/////////////////////////////////////////////////////////////////////////////
//
// Lego3DManager

// VTABLE: LEGO1 0x100dbfa4
// SIZE 0x10
class Lego3DManager {
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
	Lego3DManager();
	virtual ~Lego3DManager();

	BOOL Create(CreateStruct&);
	void Destroy();

	BOOL Add(ViewROI&);
	BOOL Remove(ViewROI&);
	BOOL Moved(ViewROI&);
	BOOL SetPointOfView(ViewROI&);

	double Render(double p_und);

	Tgl::Renderer* GetRenderer();
	Tgl::Group* GetScene();
	Lego3DView* GetLego3DView();
	// ??? for now
	ViewLODListManager* GetViewLODListManager();

private:
	Tgl::Renderer* m_pRenderer; // 0x04

	Lego3DView* m_pLego3DView;                 // 0x08
	ViewLODListManager* m_pViewLODListManager; // 0x0c
};

/////////////////////////////////////////////////////////////////////////////
//
// Lego3DManager implementaion

inline BOOL Lego3DManager::Add(ViewROI& rROI)
{
	assert(m_pLego3DView);

	return m_pLego3DView->Add(rROI);
}

inline BOOL Lego3DManager::Remove(ViewROI& rROI)
{
	assert(m_pLego3DView);

	return m_pLego3DView->Remove(rROI);
}

inline BOOL Lego3DManager::SetPointOfView(ViewROI& rROI)
{
	assert(m_pLego3DView);

	return m_pLego3DView->SetPointOfView(rROI);
}

inline BOOL Lego3DManager::Moved(ViewROI& rROI)
{
	assert(m_pLego3DView);

	return m_pLego3DView->Moved(rROI);
}

inline Tgl::Renderer* Lego3DManager::GetRenderer()
{
	return m_pRenderer;
}

inline Tgl::Group* Lego3DManager::GetScene()
{
	assert(m_pLego3DView);

	return m_pLego3DView->GetScene();
}

inline Lego3DView* Lego3DManager::GetLego3DView()
{
	return m_pLego3DView;
}

inline ViewLODListManager* Lego3DManager::GetViewLODListManager()
{
	return m_pViewLODListManager;
}

#endif /* _Lego3DManager_h */
