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

// FUNCTION: CONFIG 0x00401180
// FUNCTION: LEGO1 0x1009ba80
// FUNCTION: BETA10 0x1011d8b6
MxDriver::MxDriver(LPGUID p_guid, LPSTR p_driverDesc, LPSTR p_driverName)
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
void MxDriver::Init(LPGUID p_guid, LPSTR p_driverDesc, LPSTR p_driverName)
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

// FUNCTION: LEGO1 0x1009bd20
// FUNCTION: BETA10 0x1011dbd0
Direct3DDeviceInfo::Direct3DDeviceInfo(
	LPGUID p_guid,
	LPSTR p_deviceDesc,
	LPSTR p_deviceName,
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

// FUNCTION: LEGO1 0x1009bda0
// FUNCTION: BETA10 0x1011dca6
void Direct3DDeviceInfo::Initialize(
	LPGUID p_guid,
	LPSTR p_deviceDesc,
	LPSTR p_deviceName,
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
	m_list.push_back(driver);

	// Must be zeroed because held resources are copied by pointer only
	// and should not be freed at the end of this function
	driver.m_guid = NULL;
	driver.m_driverDesc = NULL;
	driver.m_driverName = NULL;
	memset(&driver.m_ddCaps, 0, sizeof(driver.m_ddCaps));

	LPDIRECT3D2 lpDirect3d2 = NULL;
	LPDIRECTDRAW lpDD = NULL;
	MxDriver& newDevice = m_list.back();
	HRESULT result = DirectDrawCreate(newDevice.m_guid, &lpDD, NULL);

	if (result != DD_OK) {
		BuildErrorString("DirectDraw Create failed: %s\n", EnumerateErrorToString(result));
	}
	else {
		lpDD->EnumDisplayModes(0, NULL, this, DisplayModesEnumerateCallback);
		newDevice.m_ddCaps.dwSize = sizeof(newDevice.m_ddCaps);
		result = lpDD->GetCaps(&newDevice.m_ddCaps, NULL);

		if (result != DD_OK) {
			BuildErrorString("GetCaps failed: %s\n", EnumerateErrorToString(result));
		}
		else {
			result = lpDD->QueryInterface(IID_IDirect3D2, (LPVOID*) &lpDirect3d2);

			if (result != DD_OK) {
				BuildErrorString("D3D creation failed: %s\n", EnumerateErrorToString(result));
			}
			else {
				result = lpDirect3d2->EnumDevices(DevicesEnumerateCallback, this);

				if (result != DD_OK) {
					BuildErrorString("D3D enum devices failed: %s\n", EnumerateErrorToString(result));
				}
				else {
					if (newDevice.m_devices.empty()) {
						m_list.pop_back();
					}
				}
			}
		}
	}

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
	MxDisplayMode displayMode;
	displayMode.m_width = p_ddsd->dwWidth;
	displayMode.m_height = p_ddsd->dwHeight;
	displayMode.m_bitsPerPixel = p_ddsd->ddpfPixelFormat.dwRGBBitCount;

	m_list.back().m_displayModes.push_back(displayMode);
	return DDENUMRET_OK;
}

// FUNCTION: CONFIG 0x00401cd0
// FUNCTION: LEGO1 0x1009c5d0
// FUNCTION: BETA10 0x1011e32f
HRESULT MxDeviceEnumerate::EnumDevicesCallback(
	LPGUID p_guid,
	LPSTR p_deviceDesc,
	LPSTR p_deviceName,
	LPD3DDEVICEDESC p_HWDesc,
	LPD3DDEVICEDESC p_HELDesc
)
{
	Direct3DDeviceInfo device(p_guid, p_deviceDesc, p_deviceName, p_HWDesc, p_HELDesc);
	m_list.back().m_devices.push_back(device);
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
	case DDERR_GENERIC:
		return "Generic failure.";
	case DDERR_UNSUPPORTED:
		return "Action not supported.";
	case DDERR_INVALIDPARAMS:
		return "One or more of the parameters passed to the function are incorrect.";
	case DDERR_OUTOFMEMORY:
		return "DirectDraw does not have enough memory to perform the operation.";
	case DDERR_CANNOTATTACHSURFACE:
		return "This surface can not be attached to the requested surface.";
	case DDERR_ALREADYINITIALIZED:
		return "This object is already initialized.";
	case DDERR_CURRENTLYNOTAVAIL:
		return "Support is currently not available.";
	case DDERR_CANNOTDETACHSURFACE:
		return "This surface can not be detached from the requested surface.";
	case DDERR_HEIGHTALIGN:
		return "Height of rectangle provided is not a multiple of reqd alignment.";
	case DDERR_EXCEPTION:
		return "An exception was encountered while performing the requested operation.";
	case DDERR_INVALIDCAPS:
		return "One or more of the caps bits passed to the callback are incorrect.";
	case DDERR_INCOMPATIBLEPRIMARY:
		return "Unable to match primary surface creation request with existing primary surface.";
	case DDERR_INVALIDMODE:
		return "DirectDraw does not support the requested mode.";
	case DDERR_INVALIDCLIPLIST:
		return "DirectDraw does not support the provided cliplist.";
	case DDERR_INVALIDPIXELFORMAT:
		return "The pixel format was invalid as specified.";
	case DDERR_INVALIDOBJECT:
		return "DirectDraw received a pointer that was an invalid DIRECTDRAW object.";
	case DDERR_LOCKEDSURFACES:
		return "Operation could not be carried out because one or more surfaces are locked.";
	case DDERR_INVALIDRECT:
		return "Rectangle provided was invalid.";
	case DDERR_NOALPHAHW:
		return "Operation could not be carried out because there is no alpha accleration hardware present or "
			   "available.";
	case DDERR_NO3D:
		return "There is no 3D present.";
	case DDERR_NOCOLORCONVHW:
		return "Operation could not be carried out because there is no color conversion hardware present or available.";
	case DDERR_NOCLIPLIST:
		return "No cliplist available.";
	case DDERR_NOCOLORKEY:
		return "Surface doesn't currently have a color key";
	case DDERR_NOCOOPERATIVELEVELSET:
		return "Create function called without DirectDraw object method SetCooperativeLevel being called.";
	case DDERR_NOEXCLUSIVEMODE:
		return "Operation requires the application to have exclusive mode but the application does not have exclusive "
			   "mode.";
	case DDERR_NOCOLORKEYHW:
		return "Operation could not be carried out because there is no hardware support of the destination color key.";
	case DDERR_NOGDI:
		return "There is no GDI present.";
	case DDERR_NOFLIPHW:
		return "Flipping visible surfaces is not supported.";
	case DDERR_NOTFOUND:
		return "Requested item was not found.";
	case DDERR_NOMIRRORHW:
		return "Operation could not be carried out because there is no hardware present or available.";
	case DDERR_NORASTEROPHW:
		return "Operation could not be carried out because there is no appropriate raster op hardware present or "
			   "available.";
	case DDERR_NOOVERLAYHW:
		return "Operation could not be carried out because there is no overlay hardware present or available.";
	case DDERR_NOSTRETCHHW:
		return "Operation could not be carried out because there is no hardware support for stretching.";
	case DDERR_NOROTATIONHW:
		return "Operation could not be carried out because there is no rotation hardware present or available.";
	case DDERR_NOTEXTUREHW:
		return "Operation could not be carried out because there is no texture mapping hardware present or available.";
	case DDERR_NOT4BITCOLOR:
		return "DirectDrawSurface is not in 4 bit color palette and the requested operation requires 4 bit color "
			   "palette.";
	case DDERR_NOT4BITCOLORINDEX:
		return "DirectDrawSurface is not in 4 bit color index palette and the requested operation requires 4 bit color "
			   "index palette.";
	case DDERR_NOT8BITCOLOR:
		return "DirectDrawSurface is not in 8 bit color mode and the requested operation requires 8 bit color.";
	case DDERR_NOZBUFFERHW:
		return "Operation could not be carried out because there is no hardware support for zbuffer blitting.";
	case DDERR_NOVSYNCHW:
		return "Operation could not be carried out because there is no hardware support for vertical blank "
			   "synchronized operations.";
	case DDERR_OUTOFCAPS:
		return "The hardware needed for the requested operation has already been allocated.";
	case DDERR_NOZOVERLAYHW:
		return "Overlay surfaces could not be z layered based on their BltOrder because the hardware does not support "
			   "z layering of overlays.";
	case DDERR_COLORKEYNOTSET:
		return "No src color key specified for this operation.";
	case DDERR_OUTOFVIDEOMEMORY:
		return "DirectDraw does not have enough memory to perform the operation.";
	case DDERR_OVERLAYCANTCLIP:
		return "The hardware does not support clipped overlays.";
	case DDERR_OVERLAYCOLORKEYONLYONEACTIVE:
		return "Can only have ony color key active at one time for overlays.";
	case DDERR_PALETTEBUSY:
		return "Access to this palette is being refused because the palette is already locked by another thread.";
	case DDERR_SURFACEALREADYDEPENDENT:
		return "This surface is already a dependency of the surface it is being made a dependency of.";
	case DDERR_SURFACEALREADYATTACHED:
		return "This surface is already attached to the surface it is being attached to.";
	case DDERR_SURFACEISOBSCURED:
		return "Access to surface refused because the surface is obscured.";
	case DDERR_SURFACEBUSY:
		return "Access to this surface is being refused because the surface is already locked by another thread.";
	case DDERR_SURFACENOTATTACHED:
		return "The requested surface is not attached.";
	case DDERR_SURFACELOST:
		return "Access to this surface is being refused because the surface memory is gone. The DirectDrawSurface "
			   "object representing this surface should have Restore called on it.";
	case DDERR_TOOBIGSIZE:
		return "Size requested by DirectDraw is too large, but the individual height and width are OK.";
	case DDERR_TOOBIGHEIGHT:
		return "Height requested by DirectDraw is too large.";
	case DDERR_UNSUPPORTEDFORMAT:
		return "FOURCC format requested is unsupported by DirectDraw.";
	case DDERR_TOOBIGWIDTH:
		return "Width requested by DirectDraw is too large.";
	case DDERR_VERTICALBLANKINPROGRESS:
		return "Vertical blank is in progress.";
	case DDERR_UNSUPPORTEDMASK:
		return "Bitmask in the pixel format requested is unsupported by DirectDraw.";
	case DDERR_XALIGN:
		return "Rectangle provided was not horizontally aligned on required boundary.";
	case DDERR_WASSTILLDRAWING:
		return "Informs DirectDraw that the previous Blt which is transfering information to or from this Surface is "
			   "incomplete.";
	case DDERR_INVALIDDIRECTDRAWGUID:
		return "The GUID passed to DirectDrawCreate is not a valid DirectDraw driver identifier.";
	case DDERR_DIRECTDRAWALREADYCREATED:
		return "A DirectDraw object representing this driver has already been created for this process.";
	case DDERR_NODIRECTDRAWHW:
		return "A hardware-only DirectDraw object creation was attempted but the driver did not support any hardware.";
	case DDERR_PRIMARYSURFACEALREADYEXISTS:
		return "This process already has created a primary surface.";
	case DDERR_NOEMULATION:
		return "Software emulation not available.";
	case DDERR_REGIONTOOSMALL:
		return "Region passed to Clipper::GetClipList is too small.";
	case DDERR_CLIPPERISUSINGHWND:
		return "An attempt was made to set a cliplist for a clipper object that is already monitoring an hwnd.";
	case DDERR_NOCLIPPERATTACHED:
		return "No clipper object attached to surface object.";
	case DDERR_NOHWND:
		return "Clipper notification requires an HWND or no HWND has previously been set as the CooperativeLevel HWND.";
	case DDERR_HWNDSUBCLASSED:
		return "HWND used by DirectDraw CooperativeLevel has been subclassed, this prevents DirectDraw from restoring "
			   "state.";
	case DDERR_HWNDALREADYSET:
		return "The CooperativeLevel HWND has already been set. It can not be reset while the process has surfaces or "
			   "palettes created.";
	case DDERR_NOPALETTEATTACHED:
		return "No palette object attached to this surface.";
	case DDERR_NOPALETTEHW:
		return "No hardware support for 16 or 256 color palettes.";
	case DDERR_BLTFASTCANTCLIP:
		return "Return if a clipper object is attached to the source surface passed into a BltFast call.";
	case DDERR_NOBLTHW:
		return "No blitter hardware present.";
	case DDERR_NODDROPSHW:
		return "No DirectDraw ROP hardware.";
	case DDERR_OVERLAYNOTVISIBLE:
		return "Returned when GetOverlayPosition is called on a hidden overlay.";
	case DDERR_NOOVERLAYDEST:
		return "Returned when GetOverlayPosition is called on an overlay that UpdateOverlay has never been called on "
			   "to establish a destination.";
	case DDERR_INVALIDPOSITION:
		return "Returned when the position of the overlay on the destination is no longer legal for that destination.";
	case DDERR_NOTAOVERLAYSURFACE:
		return "Returned when an overlay member is called for a non-overlay surface.";
	case DDERR_EXCLUSIVEMODEALREADYSET:
		return "An attempt was made to set the cooperative level when it was already set to exclusive.";
	case DDERR_NOTFLIPPABLE:
		return "An attempt has been made to flip a surface that is not flippable.";
	case DDERR_CANTDUPLICATE:
		return "Can't duplicate primary & 3D surfaces, or surfaces that are implicitly created.";
	case DDERR_NOTLOCKED:
		return "Surface was not locked.  An attempt to unlock a surface that was not locked at all, or by this "
			   "process, has been attempted.";
	case DDERR_CANTCREATEDC:
		return "Windows can not create any more DCs.";
	case DDERR_NODC:
		return "No DC was ever created for this surface.";
	case DDERR_WRONGMODE:
		return "This surface can not be restored because it was created in a different mode.";
	case DDERR_IMPLICITLYCREATED:
		return "This surface can not be restored because it is an implicitly created surface.";
	case DDERR_NOTPALETTIZED:
		return "The surface being used is not a palette-based surface.";
	default:
		return "Unrecognized error value.";
	}
}

// FUNCTION: CONFIG 0x00402560
// FUNCTION: LEGO1 0x1009ce60
// FUNCTION: BETA10 0x1011c7e0
int MxDeviceEnumerate::ParseDeviceName(const char* p_deviceId)
{
	if (!IsInitialized()) {
		return -1;
	}

	int unknown = -1;
	int num = -1;
	int hex[4];

	if (sscanf(p_deviceId, "%d 0x%x 0x%x 0x%x 0x%x", &num, &hex[0], &hex[1], &hex[2], &hex[3]) != 5) {
		return -1;
	}

	if (num < 0) {
		return -1;
	}

	GUID guid;
	memcpy(&guid, hex, sizeof(guid));

	int result = ProcessDeviceBytes(num, guid);

	if (result < 0) {
		result = ProcessDeviceBytes(-1, guid);
	}

	return result;
}

// FUNCTION: CONFIG 0x00402620
// FUNCTION: LEGO1 0x1009cf20
// FUNCTION: BETA10 0x1011c8b3
int MxDeviceEnumerate::ProcessDeviceBytes(int p_deviceNum, GUID& p_guid)
{
	if (!IsInitialized()) {
		return -1;
	}

	int i = 0;
	int j = 0;

	struct GUID4 {
		int m_data1;
		int m_data2;
		int m_data3;
		int m_data4;
	};

	static_assert(sizeof(GUID4) == sizeof(GUID), "Equal size");

	GUID4 deviceGuid;
	memcpy(&deviceGuid, &p_guid, sizeof(GUID4));

	for (list<MxDriver>::iterator it = m_list.begin(); it != m_list.end(); it++) {
		if (p_deviceNum >= 0 && p_deviceNum < i) {
			return -1;
		}

		GUID4 compareGuid;
		MxDriver& driver = *it;
		for (list<Direct3DDeviceInfo>::iterator it2 = driver.m_devices.begin(); it2 != driver.m_devices.end(); it2++) {
			memcpy(&compareGuid, (*it2).m_guid, sizeof(GUID4));

			if (compareGuid.m_data1 == deviceGuid.m_data1 && compareGuid.m_data2 == deviceGuid.m_data2 &&
				compareGuid.m_data3 == deviceGuid.m_data3 && compareGuid.m_data4 == deviceGuid.m_data4 &&
				i == p_deviceNum) {
				return j;
			}

			j++;
		}

		i++;
	}

	return -1;
}

// FUNCTION: CONFIG 0x00402730
// FUNCTION: LEGO1 0x1009d030
// FUNCTION: BETA10 0x1011ca54
int MxDeviceEnumerate::GetDevice(int p_deviceNum, MxDriver*& p_driver, Direct3DDeviceInfo*& p_device)
{
	if (p_deviceNum < 0 || !IsInitialized()) {
		return -1;
	}

	int i = 0;

	for (list<MxDriver>::iterator it = m_list.begin(); it != m_list.end(); it++) {
		p_driver = &*it;

		for (list<Direct3DDeviceInfo>::iterator it2 = p_driver->m_devices.begin(); it2 != p_driver->m_devices.end();
			 it2++) {
			if (i == p_deviceNum) {
				p_device = &*it2;
				return 0;
			}
			i++;
		}
	}

	return -1;
}

#if defined(MXDIRECTX_FOR_CONFIG) || defined(_DEBUG)
// FUNCTION: CONFIG 0x004027d0
// FUNCTION: BETA10 0x1011cb70
int MxDeviceEnumerate::FormatDeviceName(char* p_buffer, const MxDriver* p_driver, const Direct3DDeviceInfo* p_device)
	const
{
	int number = 0;
	for (list<MxDriver>::const_iterator it = m_list.begin(); it != m_list.end(); it++) {
		if (&(*it) == p_driver) {
			sprintf(
				p_buffer,
				"%d 0x%x 0x%x 0x%x 0x%x",
				number,
				((DWORD*) (p_device->m_guid))[0],
				((DWORD*) (p_device->m_guid))[1],
				((DWORD*) (p_device->m_guid))[2],
				((DWORD*) (p_device->m_guid))[3]
			);
			return 0;
		}
		number++;
	}
	return -1;
}
#endif

// FUNCTION: CONFIG 0x00402860
// FUNCTION: LEGO1 0x1009d0d0
int MxDeviceEnumerate::FUN_1009d0d0()
{
	if (!m_initialized) {
		return -1;
	}

	if (m_list.empty()) {
		return -1;
	}

	int i = 0;
	int j = 0;
	int k = -1;
	int cpu_mmx = SupportsMMX();

	for (list<MxDriver>::iterator it = m_list.begin();; it++) {
		if (it == m_list.end()) {
			return k;
		}

		for (list<Direct3DDeviceInfo>::iterator it2 = (*it).m_devices.begin(); it2 != (*it).m_devices.end(); it2++) {
			if ((*it2).m_HWDesc.dcmColorModel) {
				return j;
			}

			if ((cpu_mmx && (*it2).m_HELDesc.dcmColorModel == D3DCOLOR_RGB && i == 0) ||
				((*it2).m_HELDesc.dcmColorModel == D3DCOLOR_MONO && i == 0 && k < 0)) {
				k = j;
			}

			j++;
		}

		i++;
	}
}

// FUNCTION: CONFIG 0x00402930
// FUNCTION: LEGO1 0x1009d1a0
int MxDeviceEnumerate::SupportsMMX()
{
	if (!SupportsCPUID()) {
		return 0;
	}
	int supports_mmx;
#ifdef _MSC_VER
	__asm {
      mov eax, 0x0            ; EAX=0: Highest Function Parameter and Manufacturer ID
#if _MSC_VER > 1100
      cpuid                   ; Run CPUID
#else
      __emit 0x0f
      __emit 0xa2
#endif
      mov eax, 0x1            ; EAX=1: Processor Info and Feature Bits (unused)
#if _MSC_VER > 1100
      cpuid                   ; Run CPUID
#else
      __emit 0x0f
      __emit 0xa2
#endif
      xor eax, eax            ; Zero EAX register
      bt edx, 0x17            ; Test bit 0x17 (23): MMX instructions (64-bit SIMD) (Store in CF)
      adc eax, eax            ; Add with carry: EAX = EAX + EAX + CF = CF
      mov supports_mmx, eax   ; Save eax into C variable
	}
#else
	__asm__("movl $0x0, %%eax\n\t"  // EAX=0: Highest Function Parameter and Manufacturer ID
			"cpuid\n\t"             // Run CPUID\n"
			"mov $0x1, %%eax\n\t"   // EAX=1: Processor Info and Feature Bits (unused)
			"cpuid\n\t"             // Run CPUID
			"xorl %%eax, %%eax\n\t" // Zero EAX register
			"btl $0x15, %%edx\n\t"  // Test bit 0x17 (23): MMX instructions (64-bit SIMD) (Store in CF)
			"adc %%eax, %%eax"      // Add with carry: EAX = EAX + EAX + CF = CF
			: "=a"(supports_mmx)    // supports_mmx == EAX
	);
#endif
	return supports_mmx;
}

// FUNCTION: CONFIG 0x00402970
// FUNCTION: LEGO1 0x1009d1e0
int MxDeviceEnumerate::SupportsCPUID()
{
	int has_cpuid;
#ifdef _MSC_VER
#if defined(_M_IX86)
	__asm {
    xor eax, eax                    ; Zero EAX register
    pushfd                          ; Push EFLAGS register value on the stack
    or dword ptr[esp], 0x200000     ; Set bit 0x200000: Able to use CPUID instruction (Pentium+)
    popfd                           ; Write the updated value into the EFLAGS register
    pushfd                          ; Push EFLAGS register value on the stack (again)
    btr dword ptr[esp], 0x15        ; Test bit 0x15 (21) and reset (set CF)
    adc eax, eax                    ; Add with carry: EAX = EAX + EAX + CF = CF
    popfd                           ; Push EFLAGS register value on the stack (again, and makes sure the stack remains the same)
    mov has_cpuid, eax              ; Save eax into C variable
	}
#elif defined(_M_X64)
	has_cpuid = 1;
#else
	has_cpuid = 0;
#endif
#else
#if defined(__i386__)
	__asm__("xorl %%eax, %%eax\n\t"      // Zero EAX register
			"pushfl\n\t"                 // Push EFLAGS register value on the stack
			"orl $0x200000, (%%esp)\n\t" // Set bit 0x200000: Able to use CPUID instruction (Pentium+)
			"popfl\n\t"                  // Write the updated value into the EFLAGS register
			"pushfl\n\t"                 // Push EFLAGS register value on the stack (again)
			"btrl $0x15, (%%esp)\n\t"    // Test bit 0x15 (21) and reset (set CF)
			"adc %%eax, %%eax\n\t"       // Add with carry: EAX = EAX + EAX + CF = CF
			"popfl" // Push EFLAGS register value on the stack (again, and makes sure the stack remains the same)
			: "=a"(has_cpuid) // has_cpuid == EAX
	);
#elif defined(__x86_64__) || defined(__amd64__)
	has_cpuid = 1;
#else
	has_cpuid = 0;
#endif
#endif
	return has_cpuid;
}

// FUNCTION: CONFIG 0x004029a0
// FUNCTION: LEGO1 0x1009d210
int MxDeviceEnumerate::FUN_1009d210()
{
	if (!m_initialized) {
		return -1;
	}

	for (list<MxDriver>::iterator it = m_list.begin(); it != m_list.end();) {
		MxDriver& driver = *it;

		if (!DriverSupportsRequiredDisplayMode(driver)) {
			m_list.erase(it++);
		}
		else {
			for (list<Direct3DDeviceInfo>::iterator it2 = driver.m_devices.begin(); it2 != driver.m_devices.end();) {
				Direct3DDeviceInfo& device = *it2;

				if (!FUN_1009d3d0(device)) {
					driver.m_devices.erase(it2++);
				}
				else {
					it2++;
				}
			}

			if (driver.m_devices.empty()) {
				m_list.erase(it++);
			}
			else {
				it++;
			}
		}
	}

	return m_list.empty() ? -1 : 0;
}

// FUNCTION: CONFIG 0x00402b00
// FUNCTION: LEGO1 0x1009d370
unsigned char MxDeviceEnumerate::DriverSupportsRequiredDisplayMode(MxDriver& p_driver)
{
	for (list<MxDisplayMode>::iterator it = p_driver.m_displayModes.begin(); it != p_driver.m_displayModes.end();
		 it++) {
		if ((*it).m_width == 640 && (*it).m_height == 480) {
			if ((*it).m_bitsPerPixel == 8 || (*it).m_bitsPerPixel == 16) {
				return TRUE;
			}
		}
	}

	return FALSE;
}

// FUNCTION: CONFIG 0x00402b60
// FUNCTION: LEGO1 0x1009d3d0
unsigned char MxDeviceEnumerate::FUN_1009d3d0(Direct3DDeviceInfo& p_device)
{
	if (m_list.size() <= 0) {
		return FALSE;
	}

	if (p_device.m_HWDesc.dcmColorModel) {
		return p_device.m_HWDesc.dwDeviceZBufferBitDepth & DDBD_16 &&
			   p_device.m_HWDesc.dpcTriCaps.dwTextureCaps & D3DPTEXTURECAPS_PERSPECTIVE;
	}

	for (list<Direct3DDeviceInfo>::iterator it = m_list.front().m_devices.begin(); it != m_list.front().m_devices.end();
		 it++) {
		if ((&*it) == &p_device) {
			return TRUE;
		}
	}

	return FALSE;
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
