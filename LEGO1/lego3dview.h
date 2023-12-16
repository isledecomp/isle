#ifndef LEGO3DVIEW_H
#define LEGO3DVIEW_H

#include "viewmanager/viewmanager.h"
#include "mxtypes.h"

class LegoROI;

class Lego3DView {
public:
	inline ViewManager* GetViewManager() { return this->m_viewManager; }
	LegoROI* PickROI(MxLong p_a, MxLong p_b);

private:
	char m_pad[0x88];
	ViewManager* m_viewManager;
};

#endif // LEGO3DVIEW_H
