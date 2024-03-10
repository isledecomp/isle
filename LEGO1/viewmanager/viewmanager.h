#ifndef VIEWMANAGER_H
#define VIEWMANAGER_H

#include "decomp.h"
#include "realtime/realtimeview.h"
#include "viewroi.h"

#include <d3drm.h>

// VTABLE: LEGO1 0x100dbd88
// SIZE 0x1bc
class ViewManager {
public:
	enum Flags {
		c_bit1 = 0x01,
		c_bit2 = 0x02,
		c_bit3 = 0x04,
		c_bit4 = 0x08
	};

	ViewManager(Tgl::Renderer* pRenderer, Tgl::Group* scene, const OrientableROI* point_of_view);
	virtual ~ViewManager();

	void Remove(ViewROI* p_roi);
	void RemoveAll(ViewROI* p_roi);
	void FUN_100a65b0(ViewROI* p_roi, int p_und);
	void FUN_100a66a0(ViewROI* p_roi);
	void SetPOVSource(const OrientableROI* point_of_view);
	float FUN_100a6dc0(const BoundingSphere& p_bounding_sphere);
	ViewROI* Pick(Tgl::View* p_view, unsigned long x, unsigned long y);
	void SetResolution(int width, int height);
	void SetFrustrum(float fov, float front, float back);
	inline void FUN_100a66f0(ViewROI* p_roi, int p_und);
	void Update(float p_previousRenderTime, float);
	inline int Unknown();
	void FUN_100a6b90();

	inline static int Unknown2(float p_und1, float p_und2, ViewROI* p_roi);
	inline static int Unknown3(ViewROI* p_roi);

	inline const CompoundObject& GetROIs() { return rois; }
	inline void Add(ViewROI* p_roi) { rois.push_back(p_roi); }

	// SYNTHETIC: LEGO1 0x100a6000
	// ViewManager::`scalar deleting destructor'

private:
	Tgl::Group* scene;        // 0x04
	CompoundObject rois;      // 0x08
	RealtimeView rt_view;     // 0x14
	ROIList visible_rois;     // 0x18
	float unk0x28;            // 0x28
	float unk0x2c;            // 0x2c
	unsigned int flags;       // 0x30
	float width;              // 0x34
	float height;             // 0x38
	float view_angle;         // 0x3c
	MxMatrix pov;             // 0x40
	float front;              // 0x88
	float back;               // 0x8c
	float unk0x90[8][3];      // 0x90
	float unk0xf0[8][3];      // 0xf0
	float unk0x150[6][4];     // 0x150
	IDirect3DRM2* d3drm;      // 0x1b0
	IDirect3DRMFrame2* frame; // 0x1b4
	float seconds_allowed;    // 0x1b8
};

// TEMPLATE: LEGO1 0x10022030
// list<ROI *,allocator<ROI *> >::insert

// TEMPLATE: LEGO1 0x100a6020
// List<ROI *>::~List<ROI *>

// TEMPLATE: LEGO1 0x100a6070
// Vector<ROI const *>::~Vector<ROI const *>

// TEMPLATE: LEGO1 0x100a6f80
// vector<ROI const *,allocator<ROI const *> >::~vector<ROI const *,allocator<ROI const *> >

#endif // VIEWMANAGER_H
