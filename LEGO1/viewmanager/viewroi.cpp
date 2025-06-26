#include "viewroi.h"

#include "decomp.h"

#include <vec.h>

DECOMP_SIZE_ASSERT(ViewROI, 0xe4)

// GLOBAL: LEGO1 0x101013d8
unsigned char g_lightSupport = FALSE;

// FUNCTION: LEGO1 0x100a9eb0
float ViewROI::IntrinsicImportance() const
{
	return .5;
} // for now

// FUNCTION: LEGO1 0x100a9ec0
// FUNCTION: BETA10 0x1018c740
Tgl::Group* ViewROI::GetGeometry()
{
	return geometry;
}

// FUNCTION: LEGO1 0x100a9ed0
// FUNCTION: BETA10 0x1018c760
const Tgl::Group* ViewROI::GetGeometry() const
{
	return geometry;
}

// FUNCTION: LEGO1 0x100a9ee0
// FUNCTION: BETA10 0x1018c780
void ViewROI::UpdateWorldDataWithTransformAndChildren(const Matrix4& parent2world)
{
	OrientableROI::UpdateWorldDataWithTransformAndChildren(parent2world);
	SetGeometryTransformation();
}

// FUNCTION: BETA10 0x1018c7b0
inline void ViewROI::SetGeometryTransformation()
{
	if (geometry) {
		Tgl::FloatMatrix4 matrix;
		Matrix4 in(matrix);
		SETMAT4(in, m_local2world);
		geometry->SetTransformation(matrix);
	}
}

// FUNCTION: LEGO1 0x100a9fc0
// FUNCTION: BETA10 0x1018cad0
void ViewROI::UpdateWorldDataWithTransform(const Matrix4& p_transform)
{
	OrientableROI::UpdateWorldDataWithTransform(p_transform);
	SetGeometryTransformation();
}

// FUNCTION: LEGO1 0x100aa0a0
// FUNCTION: BETA10 0x1018cb00
void ViewROI::SetLocal2WorldWithWorldDataUpdate(const Matrix4& p_transform)
{
	OrientableROI::SetLocal2WorldWithWorldDataUpdate(p_transform);
	SetGeometryTransformation();
}

// FUNCTION: LEGO1 0x100aa180
// FUNCTION: BETA10 0x1018cb30
void ViewROI::UpdateWorldData()
{
	OrientableROI::UpdateWorldData();
	SetGeometryTransformation();
}

// FUNCTION: LEGO1 0x100aa500
unsigned char ViewROI::SetLightSupport(unsigned char p_lightSupport)
{
	unsigned char oldFlag = g_lightSupport;
	g_lightSupport = p_lightSupport;
	return oldFlag;
}
