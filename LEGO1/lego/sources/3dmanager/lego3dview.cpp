// Lego3DView.cpp : implementation file
//

#include "lego3dview.h"

#include "viewmanager/viewmanager.h"

DECOMP_SIZE_ASSERT(Lego3DView, 0xa8)

/////////////////////////////////////////////////////////////////////////////
// Lego3DView

// FUNCTION: LEGO1 0x100aae90
Lego3DView::Lego3DView()
{
	m_pViewManager = 0;
	m_previousRenderTime = 0;
	m_unk0x98 = 0;
	m_pPointOfView = 0;
}

// FUNCTION: LEGO1 0x100aaf30
Lego3DView::~Lego3DView()
{
	Destroy();
}

// FUNCTION: LEGO1 0x100aaf90
BOOL Lego3DView::Create(const TglSurface::CreateStruct& rCreateStruct, Tgl::Renderer* pRenderer)
{
	double viewAngle = 45;
	if (rCreateStruct.m_isWideViewAngle) {
		viewAngle = 90;
	}

	float frontClippingDistance = 0.1;
	float backClippingDistance = 500;

	if (!LegoView1::Create(rCreateStruct, pRenderer)) {
		return FALSE;
	}

	assert(GetView());
	GetView()->SetFrustrum(frontClippingDistance, backClippingDistance, viewAngle);

	assert(GetScene());
	assert(!m_pViewManager);

	m_pViewManager = new ViewManager(pRenderer, GetScene(), 0);
	m_pViewManager->SetResolution(GetWidth(), GetHeight());
	m_pViewManager->SetFrustrum(viewAngle, frontClippingDistance, backClippingDistance);
	m_previousRenderTime = 0;
	m_unk0x98 = 0;

	// // NOTE: a derived class must inform view manager when it configures
	// //       its (Tgl) view: calling Tgl::View::SetFrustrum() should be
	// //       accompanied by calling ViewManager::SetFrustrum()

	return TRUE;
}

// FUNCTION: LEGO1 0x100ab0b0
void Lego3DView::Destroy()
{
	if (m_pPointOfView) {
		m_pPointOfView = 0;
		m_pViewManager->SetPOVSource(0);
	}

	delete m_pViewManager;
	m_pViewManager = 0;

	LegoView1::Destroy();
}

// FUNCTION: LEGO1 0x100ab100
BOOL Lego3DView::Add(ViewROI& rROI)
{
	assert(m_pViewManager);

	m_pViewManager->Add(&rROI);

	return TRUE;
}

// FUNCTION: LEGO1 0x100ab170
BOOL Lego3DView::Remove(ViewROI& rROI)
{
	assert(m_pViewManager);

	m_pViewManager->Remove(&rROI);

	if (m_pPointOfView == &rROI) {
		m_pPointOfView = 0;
		m_pViewManager->SetPOVSource(0);
	}

	return TRUE;
}

// FUNCTION: LEGO1 0x100ab1b0
BOOL Lego3DView::SetPointOfView(ViewROI& rROI)
{
	Tgl::FloatMatrix4 transformation;
	Matrix4 mat(transformation);
	Tgl::Result result;

	m_pPointOfView = &rROI;

	assert(m_pViewManager);
	m_pViewManager->SetPOVSource(m_pPointOfView);

	assert(GetCamera());
	rROI.GetLocalTransform(mat);
	result = GetCamera()->SetTransformation(transformation);
	assert(Tgl::Succeeded(result));

	return TRUE;
}

// FUNCTION: LEGO1 0x100ab210
BOOL Lego3DView::Moved(ViewROI& rROI)
{
	assert(m_pViewManager);

	if (m_pPointOfView == &rROI) {
		// move the camera
		Tgl::FloatMatrix4 transformation;
		Matrix4 mat(transformation);
		Tgl::Result result;

		assert(GetCamera());

		rROI.GetLocalTransform(mat);
		result = GetCamera()->SetTransformation(transformation);
		assert(Tgl::Succeeded(result));
		m_pViewManager->SetPOVSource(&rROI);
	}

	return TRUE;
}

// FUNCTION: LEGO1 0x100ab270
double Lego3DView::Render(double p_und)
{
	assert(m_pViewManager);
	m_pViewManager->Update(m_previousRenderTime, p_und);
	m_previousRenderTime = TglSurface::Render();
	return m_previousRenderTime;
}

// FUNCTION: LEGO1 0x100ab2b0
ViewROI* Lego3DView::Pick(unsigned long x, unsigned long y)
{
	return m_pViewManager->Pick(GetView(), x, y);
}
