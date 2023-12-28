#ifndef LEGO3DMANAGER_H
#define LEGO3DMANAGER_H

#include "lego3dview.h"

class MxUnknown100dbdbc;

// VTABLE: LEGO1 0x100dbfa4
// SIZE 0x10
class Lego3DManager {
public:
	Lego3DManager();
	virtual ~Lego3DManager();

	inline Lego3DView* GetLego3DView() { return this->m_3dView; }

private:
	Tgl::Renderer* m_render;      // 0x04
	Lego3DView* m_3dView;         // 0x08
	MxUnknown100dbdbc* m_unk0x0c; // 0x0c

	void Init(MxRenderSettings& p_settings);
	void Destroy();
};

// SYNTHETIC: LEGO1 0x100ab340
// Lego3DManager::`scalar deleting destructor'

#endif // LEGO3DMANAGER_H
