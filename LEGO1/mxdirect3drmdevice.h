
#include "d3drm.h"
#include "mxdirect3drmobject.h"
#include "mxtypes.h"

// VTABLE 0x100db9b8
class IMxDirect3DRMDevice : public IMxDirect3DRMObject {
public:
	virtual ~IMxDirect3DRMDevice() {}

	virtual IUnknown** GetHandle() = 0;
};

enum MxDirect3DRMDeviceQuality {
	Wireframe = 0x0,
	UnlitFlat = 0x1,
	Flat = 0x2,
	Gouraud = 0x3,
	Phong = 0x4,
};

// VTABLE 0x100db988
class MxDirect3DRMDevice : public IMxDirect3DRMDevice {
public:
	MxDirect3DRMDevice() {}
	virtual ~MxDirect3DRMDevice() {}

	virtual IUnknown** GetHandle();

	// 0x08 in vtable
	virtual int GetWidth();
	virtual int GetHeight();

	// 0x10 in vtable
	virtual int unknown1();
	virtual int SetQuality(MxDirect3DRMDeviceQuality p_quality);
	virtual int SetShades(MxU32 p_shades);
	virtual int SetDither(int p_dither);

	// 0x20 in vtable
	virtual int Update();
	virtual void InitFromD3D();
	virtual void Init();

private:
	IDirect3DRMDevice* m_pD3DRMDevice;
};
