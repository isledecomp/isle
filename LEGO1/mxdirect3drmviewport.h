
#include "mxdirect3drmclasses.h"

// VTABLE 0x100dba28
class IMxDirect3DRMViewport : public IMxDirect3DRMObject {
public:
	virtual ~IMxDirect3DRMViewport() {}

	virtual IUnknown** GetHandle() = 0;

	// vtable+0x08
	virtual int AddLight(MxDirect3DRMFrame* p_frame) = 0;
	virtual int DeleteLight(MxDirect3DRMFrame* p_frame) = 0;

	// vtable+0x10
	virtual int SetCamera(MxDirect3DRMFrame* p_camera) = 0;
	virtual int SetProjection(int p_type) = 0;
	virtual int SetPlanes(float p_near, float p_far, float p_FoV) = 0;
	virtual int SetBackgroundRGB(float p_r, float p_g, float p_b) = 0;

	// vtable+0x20
	virtual int GetBackgroundRGB(float* p_r, float* p_g, float* p_b) = 0;
	virtual int Clear() = 0;
	virtual int SetCameraParent(MxDirect3DRMFrame* p_frame) = 0;
	virtual int ForceUpdate(int x, int y, int width, int height) = 0;

	// vtable+0x30
	virtual int Transform(float* p_shiftByVector3, float* p_out) = 0;
	virtual int InverseTransform(D3DRMVECTOR4D* p_in, float* p_outVector3) = 0;
	virtual int unk(int p_1, int p_2, int p_3, int p_4, int p_5, int p_6) = 0;
};

struct MxDirect3DRMViewportData;

// VTABLE 0x100db9e8
class MxDirect3DRMViewport : public IMxDirect3DRMViewport {
public:
	MxDirect3DRMViewport() {}
	virtual ~MxDirect3DRMViewport() {}

	virtual IUnknown** GetHandle();
	IDirect3DRMViewport* GetViewport() { return m_pDirect3DRMViewport; }

	// vtable+0x08
	virtual int AddLight(MxDirect3DRMFrame* p_frame);
	virtual int DeleteLight(MxDirect3DRMFrame* p_frame);

	// vtable+0x10
	virtual int SetCamera(MxDirect3DRMFrame* p_camera);
	virtual int SetProjection(int p_type);
	virtual int SetPlanes(float p_near, float p_far, float p_FoV);
	virtual int SetBackgroundRGB(float p_r, float p_g, float p_b);

	// vtable+0x20
	virtual int GetBackgroundRGB(float* p_r, float* p_g, float* p_b);
	virtual int Clear();
	virtual int SetCameraParent(MxDirect3DRMFrame* p_frame);
	virtual int ForceUpdate(int x, int y, int width, int height);

	// vtable+0x30
	virtual int Transform(float* p_shiftByVector3, float* p_out);
	virtual int InverseTransform(D3DRMVECTOR4D* p_in, float* p_outVector3);
	virtual int unk(int p_1, int p_2, int p_3, int p_4, int p_5, int p_6);

private:
	static int unkInternal(IDirect3DRMViewport* p_viewport, int p_1, int p_2, int p_3, int p_4, int p_5, int p_6);

	inline MxDirect3DRMViewportData* GetViewportData()
	{
		return (MxDirect3DRMViewportData*) m_pDirect3DRMViewport->GetAppData();
	}

	IDirect3DRMViewport* m_pDirect3DRMViewport;
};
