#ifndef VIEWMANAGER_H
#define VIEWMANAGER_H

#include "viewroi.h"

// VTABLE: LEGO1 0x100dbd88
// SIZE 0x1bc
class ViewManager {
public:
	ViewManager(Tgl::Group* scene, const OrientableROI* point_of_view);
	virtual ~ViewManager();

	__declspec(dllexport) void RemoveAll(ViewROI*);

	void SetPOVSource(const OrientableROI* point_of_view);
};

#endif // VIEWMANAGER_H
