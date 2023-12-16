#ifndef LEGO3DMANAGER_H
#define LEGO3DMANAGER_H

#include "lego3dview.h"

class Lego3DManager {
public:
	inline Lego3DView* GetLego3DView() { return this->m_3dView; }

private:
	int m_unk0x00;
	int m_unk0x04;
	Lego3DView* m_3dView; // 0x08
};

#endif // LEGO3DMANAGER_H
