#ifndef LEGO3DVIEW_H
#define LEGO3DVIEW_H

#include "viewmanager/viewmanager.h"

class Lego3DView {
public:
	inline ViewManager* GetViewManager() { return this->m_viewManager; }

private:
	char m_pad[0x88];
	ViewManager* m_viewManager;
};

#endif // LEGO3DVIEW_H
