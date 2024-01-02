#ifndef LEGO3DMANAGER_H
#define LEGO3DMANAGER_H

#include "lego3dview.h"

class ViewLODListManager;

// VTABLE: LEGO1 0x100dbfa4
// SIZE 0x10
class Lego3DManager {
public:
	// SIZE 0x28
	struct CreateStruct {
		undefined4 m_unk0x00;             // 0x00
		HWND m_hwnd;                      // 0x04
		IDirectDraw* m_directDraw;        // 0x08
		IDirectDrawSurface* m_ddSurface1; // 0x0c
		IDirectDrawSurface* m_ddSurface2; // 0x10
		IDirectDrawPalette* m_ddPalette;  // 0x14
		BOOL m_isFullScreen;              // 0x18
		MxU32 m_flags;                    // 0x1c
		IDirect3D* m_direct3d;            // 0x20
		IDirect3DDevice* m_d3dDevice;     // 0x24
	};

	Lego3DManager();
	virtual ~Lego3DManager();

	BOOL Create(CreateStruct& p_createStruct);

	inline Lego3DView* GetLego3DView() { return this->m_3dView; }
	inline ViewLODListManager* GetViewLODListManager() { return this->m_viewLODListManager; }

private:
	Tgl::Renderer* m_renderer;                // 0x04
	Lego3DView* m_3dView;                     // 0x08
	ViewLODListManager* m_viewLODListManager; // 0x0c

	void Destroy();
};

// SYNTHETIC: LEGO1 0x100ab340
// Lego3DManager::`scalar deleting destructor'

#endif // LEGO3DMANAGER_H
