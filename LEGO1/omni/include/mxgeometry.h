#ifndef MXGEOMETRY_H
#define MXGEOMETRY_H

#include "mxlist.h"
#include "mxutilities.h"

template <class T>
class MxPoint {
protected:
	T m_x;
	T m_y;

public:
	MxPoint() {}
	MxPoint(const MxPoint& p_p)
	{
		m_x = p_p.m_x;
		m_y = p_p.m_y;
	}
	MxPoint(T p_x, T p_y)
	{
		m_x = p_x;
		m_y = p_y;
	}
	T GetX() const { return m_x; }
	T GetY() const { return m_y; }
	void SetX(T p_x) { m_x = p_x; }
	void SetY(T p_y) { m_y = p_y; }
	void operator+=(const MxPoint& p_p)
	{
		m_x += p_p.m_x;
		m_y += p_p.m_y;
	}
	void operator-=(const MxPoint& p_p)
	{
		m_x -= p_p.m_x;
		m_y -= p_p.m_y;
	}
	MxPoint operator+(const MxPoint& p_p) const { return MxPoint(m_x + p_p.m_x, m_y + p_p.m_y); }
	MxPoint operator-(const MxPoint& p_p) const { return MxPoint(m_x - p_p.m_x, m_y - p_p.m_y); }
};

template <class T>
class MxSize {
protected:
	T m_width;
	T m_height;

public:
	MxSize() {}
	MxSize(const MxSize& p_s)
	{
		m_width = p_s.m_width;
		m_height = p_s.m_height;
	}
	MxSize(T p_width, T p_height)
	{
		m_width = p_width;
		m_height = p_height;
	}
	T GetWidth() const { return m_width; }
	T GetHeight() const { return m_height; }
	void SetWidth(T p_width) { m_width = p_width; }
	void SetHeight(T p_height) { m_height = p_height; }
};

template <class T>
class MxRect {
protected:
	T m_left;
	T m_top;
	T m_right;
	T m_bottom;

public:
	MxRect() {}
	MxRect(const MxRect& p_r)
	{
		m_left = p_r.m_left;
		m_top = p_r.m_top;
		m_right = p_r.m_right;
		m_bottom = p_r.m_bottom;
	}
	MxRect(T p_l, T p_t, T p_r, T p_b)
	{
		m_left = p_l;
		m_top = p_t;
		m_right = p_r;
		m_bottom = p_b;
	}
	MxRect(const MxPoint<T>& p_p, const MxSize<T>& p_s)
	{
		m_left = p_p.GetX();
		m_top = p_p.GetY();
		m_right = p_p.GetX() + p_s.GetWidth() - 1;
		m_bottom = p_p.GetY() + p_s.GetHeight() - 1;
	}
	T GetLeft() const { return m_left; }
	void SetLeft(T p_left) { m_left = p_left; }
	T GetTop() const { return m_top; }
	void SetTop(T p_top) { m_top = p_top; }
	T GetRight() const { return m_right; }
	void SetRight(T p_right) { m_right = p_right; }
	T GetBottom() const { return m_bottom; }
	void SetBottom(T p_bottom) { m_bottom = p_bottom; }
	T GetWidth() const { return (m_right - m_left + 1); }
	T GetHeight() const { return (m_bottom - m_top + 1); }
	MxPoint<T> GetLT() const { return MxPoint<T>(m_left, m_top); }
	MxPoint<T> GetRB() const { return MxPoint<T>(m_right, m_bottom); }
	MxBool Empty() const { return m_left >= m_right || m_top >= m_bottom; }
	MxBool Contains(const MxPoint<T>& p_p) const
	{
		return p_p.GetX() >= m_left && p_p.GetX() <= m_right && p_p.GetY() >= m_top && p_p.GetY() <= m_bottom;
	}
	MxBool Intersects(const MxRect& p_r) const
	{
		return p_r.m_right > m_left && p_r.m_left < m_right && p_r.m_bottom > m_top && p_r.m_top < m_bottom;
	}
	void operator=(const MxRect& p_r)
	{
		m_left = p_r.m_left;
		m_top = p_r.m_top;
		m_right = p_r.m_right;
		m_bottom = p_r.m_bottom;
	}
	MxBool operator==(const MxRect& p_r) const
	{
		return m_left == p_r.m_left && m_top == p_r.m_top && m_right == p_r.m_right && m_bottom == p_r.m_bottom;
	}
	MxBool operator!=(const MxRect& p_r) const { return !operator==(p_r); }
	void operator+=(const MxPoint<T>& p_p)
	{
		m_left += p_p.GetX();
		m_top += p_p.GetY();
		m_right += p_p.GetX();
		m_bottom += p_p.GetY();
	}
	void operator-=(const MxPoint<T>& p_p)
	{
		m_left -= p_p.GetX();
		m_top -= p_p.GetY();
		m_right -= p_p.GetX();
		m_bottom -= p_p.GetY();
	}
	void operator&=(const MxRect& p_r)
	{
		m_left = Max(p_r.m_left, m_left);
		m_top = Max(p_r.m_top, m_top);
		m_right = Min(p_r.m_right, m_right);
		m_bottom = Min(p_r.m_bottom, m_bottom);
	}
	void operator|=(const MxRect& p_r)
	{
		m_left = Min(p_r.m_left, m_left);
		m_top = Min(p_r.m_top, m_top);
		m_right = Max(p_r.m_right, m_right);
		m_bottom = Max(p_r.m_bottom, m_bottom);
	}
	MxRect operator+(const MxPoint<T>& p_p) const
	{
		return MxRect(m_left + p_p.GetX(), m_top + p_p.GetY(), m_left + p_p.GetX(), m_bottom + p_p.GetY());
	}
	MxRect operator-(const MxPoint<T>& p_p) const
	{
		return MxRect(m_left - p_p.GetX(), m_top - p_p.GetY(), m_left - p_p.GetX(), m_bottom - p_p.GetY());
	}
	MxRect operator&(const MxRect& p_r) const
	{
		return MxRect(
			Max(p_r.m_left, m_left),
			Max(p_r.m_top, m_top),
			Min(p_r.m_right, m_right),
			Min(p_r.m_bottom, m_bottom)
		);
	}
	MxRect operator|(const MxRect& p_r) const
	{
		return MxRect(
			Min(p_r.m_left, m_left),
			Min(p_r.m_top, m_top),
			Max(p_r.m_right, m_right),
			Max(p_r.m_bottom, m_bottom)
		);
	}
};

/******************************* MxPoint16 **********************************/

// SIZE 0x04
class MxPoint16 : public MxPoint<MxS16> {
public:
	MxPoint16() {}
	MxPoint16(const MxPoint16& p_p) : MxPoint<MxS16>(p_p) {}
	MxPoint16(MxS16 p_x, MxS16 p_y) : MxPoint<MxS16>(p_x, p_y) {}
};

class MxPoint16List : public MxPtrList<MxPoint16> {
public:
	MxPoint16List(MxBool p_ownership) : MxPtrList<MxPoint16>(p_ownership) {}
};

class MxPoint16ListCursor : public MxPtrListCursor<MxPoint16> {
public:
	MxPoint16ListCursor(MxPoint16List* p_list) : MxPtrListCursor<MxPoint16>(p_list) {}
};

/******************************* MxPoint32 **********************************/

// SIZE 0x08
class MxPoint32 : public MxPoint<MxS32> {
public:
	// FUNCTION: BETA10 0x10054d10
	MxPoint32() {}

	// FUNCTION: BETA10 0x10031a50
	MxPoint32(const MxPoint32& p_p) : MxPoint<MxS32>(p_p) {}

	// FUNCTION: LEGO1 0x10012170
	// FUNCTION: BETA10 0x1006aa70
	MxPoint32(MxS32 p_x, MxS32 p_y) : MxPoint<MxS32>(p_x, p_y) {}
};

class MxPoint32List : public MxPtrList<MxPoint32> {
public:
	MxPoint32List(MxBool p_ownership) : MxPtrList<MxPoint32>(p_ownership) {}
};

class MxPoint32ListCursor : public MxPtrListCursor<MxPoint32> {
public:
	MxPoint32ListCursor(MxPoint32List* p_list) : MxPtrListCursor<MxPoint32>(p_list) {}
};

// TEMPLATE: BETA10 0x10031a80
// ??0?$MxPoint@H@@QAE@ABV0@@Z

// TEMPLATE: BETA10 0x100318f0
// MxPoint<int>::GetX

// TEMPLATE: BETA10 0x10031920
// MxPoint<int>::GetY

// TEMPLATE: BETA10 0x10031cf0
// ??0?$MxPoint@H@@QAE@HH@Z

// TEMPLATE: BETA10 0x10054d40
// ??0?$MxPoint@H@@QAE@XZ

// TEMPLATE: BETA10 0x10142c90
// MxPoint<int>::SetX

// TEMPLATE: BETA10 0x10142cb0
// MxPoint<int>::SetY

/******************************** MxSize16 **********************************/

// SIZE 0x04
class MxSize16 : public MxSize<MxS16> {
public:
	MxSize16() {}
	MxSize16(const MxSize16& p_s) : MxSize<MxS16>(p_s) {}
	MxSize16(MxS16 p_width, MxS16 p_height) : MxSize<MxS16>(p_width, p_height) {}
};

class MxSize16List : public MxPtrList<MxSize16> {
public:
	MxSize16List(MxBool p_ownership) : MxPtrList<MxSize16>(p_ownership) {}
};

class MxSize16ListCursor : public MxPtrListCursor<MxSize16> {
public:
	MxSize16ListCursor(MxSize16List* p_list) : MxPtrListCursor<MxSize16>(p_list) {}
};

/******************************** MxSize32 **********************************/

// SIZE 0x08
class MxSize32 : public MxSize<MxS32> {
public:
	MxSize32() {}
	MxSize32(const MxSize32& p_s) : MxSize<MxS32>(p_s) {}

	// FUNCTION: BETA10 0x10137030
	MxSize32(MxS32 p_width, MxS32 p_height) : MxSize<MxS32>(p_width, p_height) {}
};

class MxSize32List : public MxPtrList<MxSize32> {
public:
	MxSize32List(MxBool p_ownership) : MxPtrList<MxSize32>(p_ownership) {}
};

class MxSize32ListCursor : public MxPtrListCursor<MxSize32> {
public:
	MxSize32ListCursor(MxSize32List* p_list) : MxPtrListCursor<MxSize32>(p_list) {}
};

// TEMPLATE: BETA10 0x10031820
// ??0?$MxSize@H@@QAE@HH@Z

// TEMPLATE: BETA10 0x10031950
// MxSize<int>::GetWidth

// TEMPLATE: BETA10 0x10031980
// MxSize<int>::GetHeight

/******************************** MxRect16 **********************************/

// SIZE 0x08
class MxRect16 : public MxRect<MxS16> {
public:
	// FUNCTION: BETA10 0x10097eb0
	MxRect16() {}
	MxRect16(const MxRect16& p_r) : MxRect<MxS16>(p_r) {}
	MxRect16(MxS16 p_l, MxS16 p_t, MxS16 p_r, MxS16 p_b) : MxRect<MxS16>(p_l, p_t, p_r, p_b) {}
	MxRect16(MxPoint16& p_p, MxSize16& p_s) : MxRect<MxS16>(p_p, p_s) {}
};

class MxRect16List : public MxPtrList<MxRect16> {
public:
	MxRect16List(MxBool p_ownership) : MxPtrList<MxRect16>(p_ownership) {}
};

class MxRect16ListCursor : public MxPtrListCursor<MxRect16> {
public:
	MxRect16ListCursor(MxRect16List* p_list) : MxPtrListCursor<MxRect16>(p_list) {}
};

// TEMPLATE: BETA10 0x10097ee0
// ??0?$MxRect@F@@QAE@XZ

// TEMPLATE: BETA10 0x100981f0
// MxRect<short>::SetLeft

// TEMPLATE: BETA10 0x10098220
// MxRect<short>::SetTop

// TEMPLATE: BETA10 0x10098250
// MxRect<short>::SetRight

// TEMPLATE: BETA10 0x10098280
// MxRect<short>::SetBottom

// TEMPLATE: BETA10 0x10098300
// MxRect<short>::GetLeft

// TEMPLATE: BETA10 0x10098330
// MxRect<short>::GetTop

// TEMPLATE: BETA10 0x10098360
// MxRect<short>::GetBottom

// TEMPLATE: BETA10 0x10098390
// MxRect<short>::GetWidth

// TEMPLATE: BETA10 0x100983c0
// MxRect<short>::GetHeight

/******************************** MxRect32 **********************************/

// SIZE 0x10
class MxRect32 : public MxRect<MxS32> {
public:
	// FUNCTION: BETA10 0x1012df70
	MxRect32() {}

	// FUNCTION: BETA10 0x1012de40
	MxRect32(const MxRect32& p_r) : MxRect<MxS32>(p_r) {}

	// FUNCTION: BETA10 0x100d8e90
	MxRect32(MxS32 p_l, MxS32 p_t, MxS32 p_r, MxS32 p_b) : MxRect<MxS32>(p_l, p_t, p_r, p_b) {}

#ifndef COMPAT_MODE
	// FUNCTION: BETA10 0x10137060
	MxRect32(MxPoint32& p_p, MxSize32& p_s) : MxRect<MxS32>(p_p, p_s) {}
#else
	MxRect32(const MxPoint32& p_p, const MxSize32& p_s) : MxRect<MxS32>(p_p, p_s) {}
#endif
};

// VTABLE: LEGO1 0x100dc3f0
// VTABLE: BETA10 0x101c1fb8
// SIZE 0x18
class MxRect32List : public MxPtrList<MxRect32> {
public:
	// FUNCTION: BETA10 0x1013b980
	MxRect32List(MxBool p_ownership) : MxPtrList<MxRect32>(p_ownership) {}
};

// VTABLE: LEGO1 0x100dc438
// VTABLE: BETA10 0x101c2048
// class MxListCursor<MxRect32 *>

// VTABLE: LEGO1 0x100dc408
// VTABLE: BETA10 0x101c2030
// class MxPtrListCursor<MxRect32>

// VTABLE: LEGO1 0x100dc420
// VTABLE: BETA10 0x101c2018
// SIZE 0x10
class MxRect32ListCursor : public MxPtrListCursor<MxRect32> {
public:
	// FUNCTION: BETA10 0x1013bf10
	MxRect32ListCursor(MxRect32List* p_list) : MxPtrListCursor<MxRect32>(p_list) {}
};

// TEMPLATE: BETA10 0x10031800
// ??0?$MxRect@H@@QAE@XZ

// TEMPLATE: LEGO1 0x100b6fc0
// TEMPLATE: BETA10 0x10031860
// ??0?$MxRect@H@@QAE@ABV?$MxPoint@H@@ABV?$MxSize@H@@@Z

// TEMPLATE: BETA10 0x100319b0
// MxRect<int>::operator=

// TEMPLATE: BETA10 0x100d8090
// MxRect<int>::GetWidth

// TEMPLATE: BETA10 0x100d80c0
// MxRect<int>::GetHeight

// TEMPLATE: BETA10 0x100d8ed0
// ??0?$MxRect@H@@QAE@HHHH@Z

// TEMPLATE: BETA10 0x100ec100
// MxRect<int>::GetLeft

// TEMPLATE: BETA10 0x100ec130
// MxRect<int>::GetTop

// TEMPLATE: BETA10 0x100ec160
// MxRect<int>::GetRight

// TEMPLATE: BETA10 0x100ec190
// MxRect<int>::GetBottom

// TEMPLATE: BETA10 0x100ec1c0
// MxRect<int>::operator+=

// TEMPLATE: BETA10 0x1012de70
// ??0?$MxRect@H@@QAE@ABV0@@Z

// TEMPLATE: BETA10 0x1012dec0
// MxRect<int>::operator&=

// SYNTHETIC: BETA10 0x1012dfa0
// MxRect32::operator=

// TEMPLATE: BETA10 0x10031d30
// MxRect<int>::Contains

// TEMPLATE: BETA10 0x10137090
// MxRect<int>::Intersects

// TEMPLATE: BETA10 0x10137100
// MxRect<int>::operator-=

// TEMPLATE: BETA10 0x1014b320
// MxRect<int>::operator|=

// TEMPLATE: BETA10 0x1014b2d0
// MxRect<int>::Empty

// TEMPLATE: BETA10 0x1014bd80
// MxRect<int>::SetLeft

// TEMPLATE: BETA10 0x1014b270
// MxRect<int>::SetTop

// TEMPLATE: BETA10 0x1014bda0
// MxRect<int>::SetRight

// TEMPLATE: BETA10 0x1014b2a0
// MxRect<int>::SetBottom

// VTABLE: LEGO1 0x100dc3d8
// VTABLE: BETA10 0x101c1fd0
// class MxPtrList<MxRect32>

// VTABLE: LEGO1 0x100dc450
// VTABLE: BETA10 0x101c1fe8
// class MxList<MxRect32 *>

// VTABLE: LEGO1 0x100dc468
// VTABLE: BETA10 0x101c2000
// class MxCollection<MxRect32 *>

// TEMPLATE: LEGO1 0x100b3c00
// TEMPLATE: BETA10 0x1013ba00
// MxCollection<MxRect32 *>::Compare

// TEMPLATE: LEGO1 0x100b3c10
// TEMPLATE: BETA10 0x1013bb30
// MxCollection<MxRect32 *>::MxCollection<MxRect32 *>

// TEMPLATE: LEGO1 0x100b3c80
// TEMPLATE: BETA10 0x1013bbc0
// MxCollection<MxRect32 *>::~MxCollection<MxRect32 *>

// TEMPLATE: LEGO1 0x100b3cd0
// TEMPLATE: BETA10 0x1013bc60
// MxCollection<MxRect32 *>::Destroy

// TEMPLATE: LEGO1 0x100b3ce0
// TEMPLATE: BETA10 0x1013bc70
// MxList<MxRect32 *>::~MxList<MxRect32 *>

// TEMPLATE: LEGO1 0x100b3d70
// TEMPLATE: BETA10 0x1013bd20
// MxPtrList<MxRect32>::Destroy

// SYNTHETIC: LEGO1 0x100b3d80
// SYNTHETIC: BETA10 0x1013bd50
// MxRect32List::`scalar deleting destructor'

// TEMPLATE: LEGO1 0x100b3df0
// TEMPLATE: BETA10 0x1013bd90
// MxPtrList<MxRect32>::~MxPtrList<MxRect32>

// SYNTHETIC: LEGO1 0x100b3e40
// SYNTHETIC: BETA10 0x1013bdf0
// MxCollection<MxRect32 *>::`scalar deleting destructor'

// SYNTHETIC: LEGO1 0x100b3eb0
// SYNTHETIC: BETA10 0x1013be30
// MxList<MxRect32 *>::`scalar deleting destructor'

// SYNTHETIC: LEGO1 0x100b3f60
// SYNTHETIC: BETA10 0x1013be70
// MxPtrList<MxRect32>::`scalar deleting destructor'

// SYNTHETIC: LEGO1 0x100b3fd0
// SYNTHETIC: BETA10 0x1013beb0
// MxRect32List::~MxRect32List

// SYNTHETIC: LEGO1 0x100b4020
// SYNTHETIC: BETA10 0x1013c0a0
// MxRect32ListCursor::`scalar deleting destructor'

// TEMPLATE: LEGO1 0x100b4090
// TEMPLATE: BETA10 0x1013c0e0
// MxPtrListCursor<MxRect32>::~MxPtrListCursor<MxRect32>

// SYNTHETIC: LEGO1 0x100b40e0
// SYNTHETIC: BETA10 0x1013c140
// MxListCursor<MxRect32 *>::`scalar deleting destructor'

// SYNTHETIC: LEGO1 0x100b4150
// SYNTHETIC: BETA10 0x1013c180
// MxPtrListCursor<MxRect32>::`scalar deleting destructor'

// TEMPLATE: LEGO1 0x100b41c0
// TEMPLATE: BETA10 0x1013c1c0
// MxListCursor<MxRect32 *>::~MxListCursor<MxRect32 *>

// SYNTHETIC: LEGO1 0x100b4210
// SYNTHETIC: BETA10 0x1013c220
// MxRect32ListCursor::~MxRect32ListCursor

// TEMPLATE: BETA10 0x1013ba20
// MxPtrList<MxRect32>::MxPtrList<MxRect32>

// TEMPLATE: BETA10 0x1013baa0
// MxList<MxRect32 *>::MxList<MxRect32 *>

// TEMPLATE: BETA10 0x1013bc30
// MxCollection<MxRect32 *>::SetDestroy

// TEMPLATE: BETA10 0x1013bce0
// MxPtrList<MxRect32>::SetOwnership

// TEMPLATE: BETA10 0x1013bf90
// MxPtrListCursor<MxRect32>::MxPtrListCursor<MxRect32>

// TEMPLATE: BETA10 0x1013c010
// MxListCursor<MxRect32 *>::MxListCursor<MxRect32 *>

// TEMPLATE: BETA10 0x1013c3c0
// MxList<MxRect32 *>::DeleteAll

// TEMPLATE: BETA10 0x1013c450
// MxListCursor<MxRect32 *>::Next

// TEMPLATE: BETA10 0x1013c610
// MxListEntry<MxRect32 *>::GetNext

// TEMPLATE: BETA10 0x1013c630
// MxListEntry<MxRect32 *>::GetValue

// TEMPLATE: BETA10 0x10152860
// MxList<MxRect32 *>::Append

// TEMPLATE: BETA10 0x10152890
// MxList<MxRect32 *>::InsertEntry

// TEMPLATE: BETA10 0x10152980
// MxListEntry<MxRect32 *>::MxListEntry<MxRect32 *>

// TEMPLATE: BETA10 0x101529c0
// MxListEntry<MxRect32 *>::SetPrev

// TEMPLATE: BETA10 0x101529f0
// MxListEntry<MxRect32 *>::SetNext

#endif // MXGEOMETRY_H
