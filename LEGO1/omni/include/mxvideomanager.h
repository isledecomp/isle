#ifndef MXVIDEOMANAGER_H
#define MXVIDEOMANAGER_H

#include "mxdisplaysurface.h"
#include "mxmediamanager.h"
#include "mxrect32.h"
#include "mxregion.h"
#include "mxvideoparam.h"

#include <d3d.h>

// VTABLE: LEGO1 0x100dc810
// SIZE 0x64
class MxVideoManager : public MxMediaManager {
public:
	MxVideoManager();
	virtual ~MxVideoManager() override;

	virtual MxResult Tickle() override; // vtable+0x8
	virtual void Destroy() override;    // vtable+0x18
	virtual MxResult VTable0x28(
		MxVideoParam& p_videoParam,
		LPDIRECTDRAW p_pDirectDraw,
		LPDIRECT3D2 p_pDirect3D,
		LPDIRECTDRAWSURFACE p_ddSurface1,
		LPDIRECTDRAWSURFACE p_ddSurface2,
		LPDIRECTDRAWCLIPPER p_ddClipper,
		MxU32 p_frequencyMS,
		MxBool p_createThread
	);                                                                                               // vtable+0x28
	virtual MxResult Create(MxVideoParam& p_videoParam, MxU32 p_frequencyMS, MxBool p_createThread); // vtable+0x2c

	__declspec(dllexport) void InvalidateRect(MxRect32&);
	__declspec(dllexport) virtual MxResult RealizePalette(MxPalette*);            // vtable+0x30
	virtual void VTable0x34(MxU32 p_x, MxU32 p_y, MxU32 p_width, MxU32 p_height); // vtable+0x34

	MxResult Init();
	void Destroy(MxBool p_fromDestructor);
	void SortPresenterList();
	void UpdateRegion();

	inline MxVideoParam& GetVideoParam() { return this->m_videoParam; }
	inline LPDIRECTDRAW GetDirectDraw() { return this->m_pDirectDraw; }
	inline MxDisplaySurface* GetDisplaySurface() { return this->m_displaySurface; }
	inline MxRegion* GetRegion() { return this->m_region; }

protected:
	MxVideoParam m_videoParam;          // 0x2c
	LPDIRECTDRAW m_pDirectDraw;         // 0x50
	LPDIRECT3D2 m_pDirect3D;            // 0x54
	MxDisplaySurface* m_displaySurface; // 0x58
	MxRegion* m_region;                 // 0x5c
	MxBool m_unk0x60;                   // 0x60
};

#endif // MXVIDEOMANAGER_H
