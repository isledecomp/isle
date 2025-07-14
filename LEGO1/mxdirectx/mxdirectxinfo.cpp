#include "mxdirectxinfo.h"

#include <assert.h>
#include <stdio.h> // for vsprintf

DECOMP_SIZE_ASSERT(MxAssignedDevice, 0xe4)
DECOMP_SIZE_ASSERT(Direct3DDeviceInfo, 0x1a4)
DECOMP_SIZE_ASSERT(MxDisplayMode, 0x0c)
DECOMP_SIZE_ASSERT(MxDriver, 0x190)
DECOMP_SIZE_ASSERT(MxDeviceEnumerate, 0x14)
DECOMP_SIZE_ASSERT(DeviceModesInfo, 0x17c)
DECOMP_SIZE_ASSERT(DeviceModesInfo::Mode, 0x0c)

// FUNCTION: LEGO1 0x1009b8b0
// FUNCTION: BETA10 0x1011c05e
MxAssignedDevice::MxAssignedDevice()
{
	memset(this, 0, sizeof(*this));
}

// FUNCTION: LEGO1 0x1009b8d0
// FUNCTION: BETA10 0x1011c08a
MxAssignedDevice::~MxAssignedDevice()
{
	if (m_deviceInfo) {
		delete m_deviceInfo;
		m_deviceInfo = NULL;
	}
}

// FUNCTION: BETA10 0x1011d7f0
MxDriver::MxDriver()
{
	m_guid = NULL;
	m_driverDesc = NULL;
	m_driverName = NULL;
	memset(&m_ddCaps, 0, sizeof(m_ddCaps));
}

// FUNCTION: CONFIG 0x00401180
// FUNCTION: LEGO1 0x1009ba80
// FUNCTION: BETA10 0x1011d8b6
MxDriver::MxDriver(LPGUID p_guid, LPCSTR p_driverDesc, LPCSTR p_driverName)
{
	m_guid = NULL;
	m_driverDesc = NULL;
	m_driverName = NULL;
	memset(&m_ddCaps, 0, sizeof(m_ddCaps));

	Init(p_guid, p_driverDesc, p_driverName);
}

// FUNCTION: CONFIG 0x401280
// FUNCTION: LEGO1 0x1009bb80
// FUNCTION: BETA10 0x1011d992
MxDriver::~MxDriver()
{
	if (m_guid) {
		delete m_guid;
	}
	if (m_driverDesc) {
		delete[] m_driverDesc;
	}
	if (m_driverName) {
		delete[] m_driverName;
	}
}

// FUNCTION: CONFIG 0x00401330
// FUNCTION: LEGO1 0x1009bc30
// FUNCTION: BETA10 0x1011da89
void MxDriver::Init(LPGUID p_guid, LPCSTR p_driverDesc, LPCSTR p_driverName)
{
	if (m_driverDesc) {
		delete[] m_driverDesc;
		m_driverDesc = NULL;
	}

	if (m_driverName) {
		delete[] m_driverName;
		m_driverName = NULL;
	}

	if (p_guid) {
		m_guid = new GUID;
		memcpy(m_guid, p_guid, sizeof(*m_guid));
	}

	if (p_driverDesc) {
		m_driverDesc = new char[strlen(p_driverDesc) + 1];
		strcpy(m_driverDesc, p_driverDesc);
	}

	if (p_driverName) {
		m_driverName = new char[strlen(p_driverName) + 1];
		strcpy(m_driverName, p_driverName);
	}
}

// FUNCTION: BETA10 0x1011dba4
Direct3DDeviceInfo::Direct3DDeviceInfo()
{
	memset(this, 0, sizeof(*this));
}

// FUNCTION: CONFIG 0x401420
// FUNCTION: LEGO1 0x1009bd20
// FUNCTION: BETA10 0x1011dbd0
Direct3DDeviceInfo::Direct3DDeviceInfo(
	LPGUID p_guid,
	LPCSTR p_deviceDesc,
	LPCSTR p_deviceName,
	LPD3DDEVICEDESC p_HWDesc,
	LPD3DDEVICEDESC p_HELDesc
)
{
	memset(this, 0, sizeof(*this));

	Initialize(p_guid, p_deviceDesc, p_deviceName, p_HWDesc, p_HELDesc);
}

// FUNCTION: CONFIG 0x401460
// FUNCTION: LEGO1 0x1009bd60
// FUNCTION: BETA10 0x1011dc1a
Direct3DDeviceInfo::~Direct3DDeviceInfo()
{
	if (m_guid) {
		delete m_guid;
	}
	if (m_deviceDesc) {
		delete[] m_deviceDesc;
	}
	if (m_deviceName) {
		delete[] m_deviceName;
	}
}

// FUNCTION: CONFIG 0x4014a0
// FUNCTION: LEGO1 0x1009bda0
// FUNCTION: BETA10 0x1011dca6
void Direct3DDeviceInfo::Initialize(
	LPGUID p_guid,
	LPCSTR p_deviceDesc,
	LPCSTR p_deviceName,
	LPD3DDEVICEDESC p_HWDesc,
	LPD3DDEVICEDESC p_HELDesc
)
{
	if (m_deviceDesc) {
		delete[] m_deviceDesc;
		m_deviceDesc = NULL;
	}

	if (m_deviceName) {
		delete[] m_deviceName;
		m_deviceName = NULL;
	}

	if (p_guid) {
		m_guid = new GUID;
		memcpy(m_guid, p_guid, sizeof(*m_guid));
	}

	if (p_deviceDesc) {
		m_deviceDesc = new char[strlen(p_deviceDesc) + 1];
		strcpy(m_deviceDesc, p_deviceDesc);
	}

	if (p_deviceName) {
		m_deviceName = new char[strlen(p_deviceName) + 1];
		strcpy(m_deviceName, p_deviceName);
	}

	// DECOMP: Beta shows implicit memcpy for these two members
	if (p_HWDesc) {
		m_HWDesc = *p_HWDesc;
	}

	if (p_HELDesc) {
		m_HELDesc = *p_HELDesc;
	}
}

// FUNCTION: CONFIG 0x004015c0
// FUNCTION: LEGO1 0x1009bec0
// FUNCTION: BETA10 0x1011ddf8
MxDeviceEnumerate::MxDeviceEnumerate()
{
	m_initialized = FALSE;
}

// FUNCTION: CONFIG 0x401710
// FUNCTION: LEGO1 0x1009c010
// FUNCTION: BETA10 0x1011de74
MxDeviceEnumerate::~MxDeviceEnumerate()
{
}

// FUNCTION: CONFIG 0x00401770
// FUNCTION: LEGO1 0x1009c070
// FUNCTION: BETA10 0x1011dedf
BOOL MxDeviceEnumerate::EnumDirectDrawCallback(LPGUID p_guid, LPSTR p_driverDesc, LPSTR p_driverName)
{
	MxDriver driver(p_guid, p_driverDesc, p_driverName);
	m_ddInfo.push_back(driver);

	// Must be zeroed because held resources are copied by pointer only
	// and should not be freed at the end of this function
	driver.m_guid = NULL;
	driver.m_driverDesc = NULL;
	driver.m_driverName = NULL;
	memset(&driver.m_ddCaps, 0, sizeof(driver.m_ddCaps));

	LPDIRECT3D2 lpDirect3d2 = NULL;
	LPDIRECTDRAW lpDD = NULL;
	MxDriver& newDevice = m_ddInfo.back();
	HRESULT result = DirectDrawCreate(newDevice.m_guid, &lpDD, NULL);

	if (result != DD_OK) {
		BuildErrorString("DirectDraw Create failed: %s\n", EnumerateErrorToString(result));
		goto done;
	}

	lpDD->EnumDisplayModes(0, NULL, this, DisplayModesEnumerateCallback);
	newDevice.m_ddCaps.dwSize = sizeof(newDevice.m_ddCaps);
	result = lpDD->GetCaps(&newDevice.m_ddCaps, NULL);

	if (result != DD_OK) {
		BuildErrorString("GetCaps failed: %s\n", EnumerateErrorToString(result));
		goto done;
	}

	result = lpDD->QueryInterface(IID_IDirect3D2, (LPVOID*) &lpDirect3d2);

	if (result != DD_OK) {
		BuildErrorString("D3D creation failed: %s\n", EnumerateErrorToString(result));
		goto done;
	}

	result = lpDirect3d2->EnumDevices(DevicesEnumerateCallback, this);

	if (result != DD_OK) {
		BuildErrorString("D3D enum devices failed: %s\n", EnumerateErrorToString(result));
		goto done;
	}

	if (!newDevice.m_devices.size()) {
		m_ddInfo.pop_back();
	}

done:
	if (lpDirect3d2) {
		lpDirect3d2->Release();
	}

	if (lpDD) {
		lpDD->Release();
	}

	return DDENUMRET_OK;
}

// FUNCTION: CONFIG 0x00401bc0
// FUNCTION: LEGO1 0x1009c4c0
// FUNCTION: BETA10 0x1011e193
void MxDeviceEnumerate::BuildErrorString(const char* p_format, ...)
{
	va_list args;
	char buf[512];

	va_start(args, p_format);
	vsprintf(buf, p_format, args);
	va_end(args);

	OutputDebugString(buf);
}

// FUNCTION: CONFIG 0x00401bf0
// FUNCTION: LEGO1 0x1009c4f0
// FUNCTION: BETA10 0x1011e1dd
HRESULT CALLBACK MxDeviceEnumerate::DisplayModesEnumerateCallback(LPDDSURFACEDESC p_ddsd, LPVOID p_context)
{
	if (p_context == NULL) {
		assert(0);
	}

	return ((MxDeviceEnumerate*) p_context)->EnumDisplayModesCallback(p_ddsd);
}

// FUNCTION: CONFIG 0x00401c10
// FUNCTION: LEGO1 0x1009c510
// FUNCTION: BETA10 0x1011e226
HRESULT CALLBACK MxDeviceEnumerate::DevicesEnumerateCallback(
	LPGUID p_guid,
	LPSTR p_deviceDesc,
	LPSTR p_deviceName,
	LPD3DDEVICEDESC p_HWDesc,
	LPD3DDEVICEDESC p_HELDesc,
	LPVOID p_context
)
{
	if (p_context == NULL) {
		assert(0);
	}

	return ((MxDeviceEnumerate*) p_context)
		->EnumDevicesCallback(p_guid, p_deviceDesc, p_deviceName, p_HWDesc, p_HELDesc);
}

// FUNCTION: CONFIG 0x00401c40
// FUNCTION: LEGO1 0x1009c540
// FUNCTION: BETA10 0x1011e27f
HRESULT MxDeviceEnumerate::EnumDisplayModesCallback(LPDDSURFACEDESC p_ddsd)
{
	assert(m_ddInfo.size() > 0);
	assert(p_ddsd);

	// TODO: compat_mode?
	MxDisplayMode displayMode(p_ddsd->dwWidth, p_ddsd->dwHeight, p_ddsd->ddpfPixelFormat.dwRGBBitCount);
	m_ddInfo.back().m_displayModes.push_back(displayMode);
	return DDENUMRET_OK;
}

// FUNCTION: CONFIG 0x00401cd0
// FUNCTION: LEGO1 0x1009c5d0
// FUNCTION: BETA10 0x1011e32f
HRESULT MxDeviceEnumerate::EnumDevicesCallback(
	LPGUID p_guid,
	LPCSTR p_deviceDesc,
	LPCSTR p_deviceName,
	LPD3DDEVICEDESC p_HWDesc,
	LPD3DDEVICEDESC p_HELDesc
)
{
	Direct3DDeviceInfo device(p_guid, p_deviceDesc, p_deviceName, p_HWDesc, p_HELDesc);
	m_ddInfo.back().m_devices.push_back(device);
	memset(&device, 0, sizeof(device));
	return DDENUMRET_OK;
}

// FUNCTION: CONFIG 0x00401dc0
// FUNCTION: LEGO1 0x1009c6c0
// FUNCTION: BETA10 0x1011e3fa
int MxDeviceEnumerate::DoEnumerate()
{
	if (IsInitialized()) {
		return -1;
	}

	HRESULT ret = DirectDrawEnumerate(DirectDrawEnumerateCallback, this);
	if (ret != DD_OK) {
		BuildErrorString("DirectDrawEnumerate returned error %s\n", EnumerateErrorToString(ret));
		return -1;
	}

	m_initialized = TRUE;
	return 0;
}

// FUNCTION: CONFIG 0x00401e10
// FUNCTION: LEGO1 0x1009c710
// FUNCTION: BETA10 0x1011e476
BOOL CALLBACK
MxDeviceEnumerate::DirectDrawEnumerateCallback(LPGUID p_guid, LPSTR p_driverDesc, LPSTR p_driverName, LPVOID p_context)
{
	if (p_context == NULL) {
		assert(0);
	}

	return ((MxDeviceEnumerate*) p_context)->EnumDirectDrawCallback(p_guid, p_driverDesc, p_driverName);
}

// FUNCTION: CONFIG 0x00401e30
// FUNCTION: LEGO1 0x1009c730
// FUNCTION: BETA10 0x1011e4c7
const char* MxDeviceEnumerate::EnumerateErrorToString(HRESULT p_error)
{
	switch (p_error) {
	case DD_OK:
		return "No error.";
	case DDERR_ALREADYINITIALIZED:
		return "This object is already initialized.";
	case DDERR_BLTFASTCANTCLIP:
		return "Return if a clipper object is attached to the source surface passed into a BltFast call.";
	case DDERR_CANNOTATTACHSURFACE:
		return "This surface can not be attached to the requested surface.";
	case DDERR_CANNOTDETACHSURFACE:
		return "This surface can not be detached from the requested surface.";
	case DDERR_CANTCREATEDC:
		return "Windows can not create any more DCs.";
	case DDERR_CANTDUPLICATE:
		return "Can't duplicate primary & 3D surfaces, or surfaces that are implicitly created.";
	case DDERR_CLIPPERISUSINGHWND:
		return "An attempt was made to set a cliplist for a clipper object that is already monitoring an hwnd.";
	case DDERR_COLORKEYNOTSET:
		return "No src color key specified for this operation.";
	case DDERR_CURRENTLYNOTAVAIL:
		return "Support is currently not available.";
	case DDERR_DIRECTDRAWALREADYCREATED:
		return "A DirectDraw object representing this driver has already been created for this process.";
	case DDERR_EXCEPTION:
		return "An exception was encountered while performing the requested operation.";
	case DDERR_EXCLUSIVEMODEALREADYSET:
		return "An attempt was made to set the cooperative level when it was already set to exclusive.";
	case DDERR_GENERIC:
		return "Generic failure.";
	case DDERR_HEIGHTALIGN:
		return "Height of rectangle provided is not a multiple of reqd alignment.";
	case DDERR_HWNDALREADYSET:
		return "The CooperativeLevel HWND has already been set. It can not be reset while the process has surfaces or "
			   "palettes created.";
	case DDERR_HWNDSUBCLASSED:
		return "HWND used by DirectDraw CooperativeLevel has been subclassed, this prevents DirectDraw from restoring "
			   "state.";
	case DDERR_IMPLICITLYCREATED:
		return "This surface can not be restored because it is an implicitly created surface.";
	case DDERR_INCOMPATIBLEPRIMARY:
		return "Unable to match primary surface creation request with existing primary surface.";
	case DDERR_INVALIDCAPS:
		return "One or more of the caps bits passed to the callback are incorrect.";
	case DDERR_INVALIDCLIPLIST:
		return "DirectDraw does not support the provided cliplist.";
	case DDERR_INVALIDDIRECTDRAWGUID:
		return "The GUID passed to DirectDrawCreate is not a valid DirectDraw driver identifier.";
	case DDERR_INVALIDMODE:
		return "DirectDraw does not support the requested mode.";
	case DDERR_INVALIDOBJECT:
		return "DirectDraw received a pointer that was an invalid DIRECTDRAW object.";
	case DDERR_INVALIDPARAMS:
		return "One or more of the parameters passed to the function are incorrect.";
	case DDERR_INVALIDPIXELFORMAT:
		return "The pixel format was invalid as specified.";
	case DDERR_INVALIDPOSITION:
		return "Returned when the position of the overlay on the destination is no longer legal for that "
			   "destination.";
	case DDERR_INVALIDRECT:
		return "Rectangle provided was invalid.";
	case DDERR_LOCKEDSURFACES:
		return "Operation could not be carried out because one or more surfaces are locked.";
	case DDERR_NO3D:
		return "There is no 3D present.";
	case DDERR_NOALPHAHW:
		return "Operation could not be carried out because there is no alpha accleration hardware present or "
			   "available.";
	case DDERR_NOBLTHW:
		return "No blitter hardware present.";
	case DDERR_NOCLIPLIST:
		return "No cliplist available.";
	case DDERR_NOCLIPPERATTACHED:
		return "No clipper object attached to surface object.";
	case DDERR_NOCOLORCONVHW:
		return "Operation could not be carried out because there is no color conversion hardware present or "
			   "available.";
	case DDERR_NOCOLORKEY:
		return "Surface doesn't currently have a color key";
	case DDERR_NOCOLORKEYHW:
		return "Operation could not be carried out because there is no hardware support of the destination color "
			   "key.";
	case DDERR_NOCOOPERATIVELEVELSET:
		return "Create function called without DirectDraw object method SetCooperativeLevel being called.";
	case DDERR_NODC:
		return "No DC was ever created for this surface.";
	case DDERR_NODDROPSHW:
		return "No DirectDraw ROP hardware.";
	case DDERR_NODIRECTDRAWHW:
		return "A hardware-only DirectDraw object creation was attempted but the driver did not support any "
			   "hardware.";
	case DDERR_NOEMULATION:
		return "Software emulation not available.";
	case DDERR_NOEXCLUSIVEMODE:
		return "Operation requires the application to have exclusive mode but the application does not have exclusive "
			   "mode.";
	case DDERR_NOFLIPHW:
		return "Flipping visible surfaces is not supported.";
	case DDERR_NOGDI:
		return "There is no GDI present.";
	case DDERR_NOHWND:
		return "Clipper notification requires an HWND or no HWND has previously been set as the CooperativeLevel "
			   "HWND.";
	case DDERR_NOMIRRORHW:
		return "Operation could not be carried out because there is no hardware present or available.";
	case DDERR_NOOVERLAYDEST:
		return "Returned when GetOverlayPosition is called on an overlay that UpdateOverlay has never been called on "
			   "to establish a destination.";
	case DDERR_NOOVERLAYHW:
		return "Operation could not be carried out because there is no overlay hardware present or available.";
	case DDERR_NOPALETTEATTACHED:
		return "No palette object attached to this surface.";
	case DDERR_NOPALETTEHW:
		return "No hardware support for 16 or 256 color palettes.";
	case DDERR_NORASTEROPHW:
		return "Operation could not be carried out because there is no appropriate raster op hardware present or "
			   "available.";
	case DDERR_NOROTATIONHW:
		return "Operation could not be carried out because there is no rotation hardware present or available.";
	case DDERR_NOSTRETCHHW:
		return "Operation could not be carried out because there is no hardware support for stretching.";
	case DDERR_NOT4BITCOLOR:
		return "DirectDrawSurface is not in 4 bit color palette and the requested operation requires 4 bit color "
			   "palette.";
	case DDERR_NOT4BITCOLORINDEX:
		return "DirectDrawSurface is not in 4 bit color index palette and the requested operation requires 4 bit color "
			   "index palette.";
	case DDERR_NOT8BITCOLOR:
		return "DirectDrawSurface is not in 8 bit color mode and the requested operation requires 8 bit color.";
	case DDERR_NOTAOVERLAYSURFACE:
		return "Returned when an overlay member is called for a non-overlay surface.";
	case DDERR_NOTEXTUREHW:
		return "Operation could not be carried out because there is no texture mapping hardware present or "
			   "available.";
	case DDERR_NOTFLIPPABLE:
		return "An attempt has been made to flip a surface that is not flippable.";
	case DDERR_NOTFOUND:
		return "Requested item was not found.";
	case DDERR_NOTLOCKED:
		return "Surface was not locked.  An attempt to unlock a surface that was not locked at all, or by this "
			   "process, has been attempted.";
	case DDERR_NOTPALETTIZED:
		return "The surface being used is not a palette-based surface.";
	case DDERR_NOVSYNCHW:
		return "Operation could not be carried out because there is no hardware support for vertical blank "
			   "synchronized operations.";
	case DDERR_NOZBUFFERHW:
		return "Operation could not be carried out because there is no hardware support for zbuffer blitting.";
	case DDERR_NOZOVERLAYHW:
		return "Overlay surfaces could not be z layered based on their BltOrder because the hardware does not support "
			   "z layering of overlays.";
	case DDERR_OUTOFCAPS:
		return "The hardware needed for the requested operation has already been allocated.";
	case DDERR_OUTOFMEMORY:
		return "DirectDraw does not have enough memory to perform the operation.";
	case DDERR_OUTOFVIDEOMEMORY:
		return "DirectDraw does not have enough memory to perform the operation.";
	case DDERR_OVERLAYCANTCLIP:
		return "The hardware does not support clipped overlays.";
	case DDERR_OVERLAYCOLORKEYONLYONEACTIVE:
		return "Can only have ony color key active at one time for overlays.";
	case DDERR_OVERLAYNOTVISIBLE:
		return "Returned when GetOverlayPosition is called on a hidden overlay.";
	case DDERR_PALETTEBUSY:
		return "Access to this palette is being refused because the palette is already locked by another thread.";
	case DDERR_PRIMARYSURFACEALREADYEXISTS:
		return "This process already has created a primary surface.";
	case DDERR_REGIONTOOSMALL:
		return "Region passed to Clipper::GetClipList is too small.";
	case DDERR_SURFACEALREADYATTACHED:
		return "This surface is already attached to the surface it is being attached to.";
	case DDERR_SURFACEALREADYDEPENDENT:
		return "This surface is already a dependency of the surface it is being made a dependency of.";
	case DDERR_SURFACEBUSY:
		return "Access to this surface is being refused because the surface is already locked by another thread.";
	case DDERR_SURFACEISOBSCURED:
		return "Access to surface refused because the surface is obscured.";
	case DDERR_SURFACELOST:
		return "Access to this surface is being refused because the surface memory is gone. The DirectDrawSurface "
			   "object representing this surface should have Restore called on it.";
	case DDERR_SURFACENOTATTACHED:
		return "The requested surface is not attached.";
	case DDERR_TOOBIGHEIGHT:
		return "Height requested by DirectDraw is too large.";
	case DDERR_TOOBIGSIZE:
		return "Size requested by DirectDraw is too large, but the individual height and width are OK.";
	case DDERR_TOOBIGWIDTH:
		return "Width requested by DirectDraw is too large.";
	case DDERR_UNSUPPORTED:
		return "Action not supported.";
	case DDERR_UNSUPPORTEDFORMAT:
		return "FOURCC format requested is unsupported by DirectDraw.";
	case DDERR_UNSUPPORTEDMASK:
		return "Bitmask in the pixel format requested is unsupported by DirectDraw.";
	case DDERR_VERTICALBLANKINPROGRESS:
		return "Vertical blank is in progress.";
	case DDERR_WASSTILLDRAWING:
		return "Informs DirectDraw that the previous Blt which is transfering information to or from this Surface is "
			   "incomplete.";
	case DDERR_WRONGMODE:
		return "This surface can not be restored because it was created in a different mode.";
	case DDERR_XALIGN:
		return "Rectangle provided was not horizontally aligned on required boundary.";
	default:
		return "Unrecognized error value.";
	}
}

// FUNCTION: LEGO1 0x1009efb0
// FUNCTION: BETA10 0x10122ee2
DeviceModesInfo::DeviceModesInfo()
{
	memset(this, 0, sizeof(*this));
}

// FUNCTION: LEGO1 0x1009efd0
// FUNCTION: BETA10 0x10122f0e
DeviceModesInfo::~DeviceModesInfo()
{
	if (m_guid != NULL) {
		delete m_guid;
	}

	if (m_modeArray != NULL) {
		delete[] m_modeArray;
	}
}
