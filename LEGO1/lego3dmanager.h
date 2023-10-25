#ifndef LEGO3DMANAGER_H
#define LEGO3DMANAGER_H

#include "lego3dview.h"

class Lego3DManager {
public:
	inline Lego3DView* GetLego3DView() { return this->m_3dView; }

private:
	int m_unk00;
	int m_unk04;
	Lego3DView* m_3dView;
};

#endif // LEGO3DMANAGER_H
