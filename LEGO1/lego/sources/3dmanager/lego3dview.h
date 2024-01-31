#ifndef _Lego3DView_h
#define _Lego3DView_h

#include "decomp.h"
#include "legoview1.h"
#include "viewmanager/viewmanager.h"

/////////////////////////////////////////////////////////////////////////////
// Lego3DView

// VTABLE: LEGO1 0x100dbf78
// SIZE 0xa8
class Lego3DView : public LegoView1 {
public:
	Lego3DView();
	~Lego3DView() override;

	BOOL Create(const CreateStruct&, Tgl::Renderer*);
	void Destroy() override; // vtable+0x08

	BOOL Add(ViewROI&);
	BOOL Remove(ViewROI&);
	BOOL Moved(ViewROI&);
	BOOL SetPointOfView(ViewROI&);

	double Render(double p_und);

	ViewROI* Pick(unsigned long x, unsigned long y);

	ViewROI* GetPointOfView();
	ViewManager* GetViewManager();
	// double GetTargetRenderingRate() const;

private:
	ViewManager* m_pViewManager; // 0x88
	double m_previousRenderTime; // 0x90
	double m_unk0x98;            // 0x98
	ViewROI* m_pPointOfView;     // 0xa0
};

// SYNTHETIC: LEGO1 0x100aaf10
// Lego3DView::`scalar deleting destructor'

/////////////////////////////////////////////////////////////////////////////
//
// Lego3DView implementation

inline ViewManager* Lego3DView::GetViewManager()
{
	return m_pViewManager;
}

inline ViewROI* Lego3DView::GetPointOfView()
{
	return m_pPointOfView;
}

#endif /* _Lego3DView_h */
