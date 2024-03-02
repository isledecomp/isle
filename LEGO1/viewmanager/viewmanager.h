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

	void RemoveAll(ViewROI*);

	void SetPOVSource(const OrientableROI* point_of_view);
	void SetResolution(int width, int height);
	void SetFrustrum(float fov, float front, float back);
	void Update(float p_previousRenderTime, float p_und2);

	// SYNTHETIC: LEGO1 0x100a6000
	// ViewManager::`scalar deleting destructor'

	inline CompoundObject& GetUnknown0x08() { return unk0x08; }

	inline void AddToUnknown0x08(ViewROI* p_roi) { unk0x08.push_back(p_roi); }

private:
	Tgl::Group* scene;        // 0x04
	CompoundObject unk0x08;   // 0x08
	RealtimeView rt_view;     // 0x14
	ROIList visible_rois;     // 0x18
	float unk0x28;            // 0x28
	undefined4 unk0x2c;       // 0x2c
	unsigned int flags;       // 0x30
	float unk0x34;            // 0x34
	float unk0x38;            // 0x38
	float unk0x3c;            // 0x3c
	MxMatrix unk0x40;         // 0x40
	float unk0x88;            // 0x88
	float unk0x8c;            // 0x8c
	undefined unk0x90[0x60];  // 0x90
	undefined unk0xf0[0x60];  // 0xf0
	undefined unk0x150[0x60]; // 0x150
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
