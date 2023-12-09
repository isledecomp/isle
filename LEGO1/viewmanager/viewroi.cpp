#include "viewroi.h"

#include "../decomp.h"

DECOMP_SIZE_ASSERT(ViewROI, 0xe0)

// FUNCTION: LEGO1 0x100a9eb0
float ViewROI::IntrinsicImportance() const
{
	return .5;
} // for now

// FUNCTION: LEGO1 0x100a9ec0
const Tgl::Group* ViewROI::GetGeometry() const
{
	return geometry;
}

// FUNCTION: LEGO1 0x100a9ed0
Tgl::Group* ViewROI::GetGeometry()
{
	return geometry;
}

// FUNCTION: LEGO1 0x100a9ee0
void ViewROI::UpdateWorldData(const Matrix4Data& parent2world)
{
	OrientableROI::UpdateWorldData(parent2world);
	if (geometry) {
		Tgl::FloatMatrix4 mat;
		SETMAT4(mat, m_local2world.GetMatrix());
		Tgl::Result result = geometry->SetTransformation(mat);
		// assert(Tgl::Succeeded(result));
	}
}

inline ViewROI::~ViewROI()
{
	// SetLODList() will decrease refCount of LODList
	SetLODList(0);
	delete geometry;
}
