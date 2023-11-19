
#include "d3d.h"
#include "d3drm.h"
#include "mxtypes.h"

// VTABLE 0x100db980
class IMxDirect3DRMObject {
public:
	virtual ~IMxDirect3DRMObject() {}

	virtual IUnknown** GetHandle() = 0;
};
