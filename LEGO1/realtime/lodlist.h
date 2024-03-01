#ifndef LODLIST_H
#define LODLIST_H

#include "assert.h"

#include <stddef.h> // size_t

class LODObject;

// disable: identifier was truncated to '255' characters in the debug information
#pragma warning(disable : 4786)

//////////////////////////////////////////////////////////////////////////////
//
// LODListBase
//
// An LODListBase is an ordered list of LODObjects
// where each successive object in the list has a more complex
// geometric representation than the one preceeding it.
//

// VTABLE: LEGO1 0x100dbdc8
// SIZE 0x10
class LODListBase {
protected:
	LODListBase(size_t capacity);

	const LODObject* PushBack(const LODObject*);
	const LODObject* PopBack();

public:
	virtual ~LODListBase();
	const LODObject* operator[](int) const;

	// current number of LODObject* in LODListBase
	size_t Size() const;

	// maximum number of LODObject* LODListBase can hold
	size_t Capacity() const;

	// SYNTHETIC: LEGO1 0x100a77b0
	// LODListBase::`scalar deleting destructor'

#ifdef _DEBUG
	virtual void Dump(void (*pTracer)(const char*, ...)) const;
#endif

private:
	// not implemented
	LODListBase(const LODListBase&);
	LODListBase& operator=(const LODListBase&);

private:
	const LODObject** m_ppLODObject; // 0x04
	size_t m_capacity;               // 0x08
	size_t m_size;                   // 0x0c
};

//////////////////////////////////////////////////////////////////////////////
//
// LODList
//

// SIZE 0x10
template <class T>
class LODList : public LODListBase {
public:
	LODList(size_t capacity);

	const T* operator[](int) const;
	const T* PushBack(const T*);
	const T* PopBack();
};

//////////////////////////////////////////////////////////////////////////////
//
// LODListBase implementation

inline LODListBase::LODListBase(size_t capacity)
	: m_capacity(capacity), m_size(0), m_ppLODObject(new const LODObject*[capacity])
{
#ifdef _DEBUG
	int i;

	for (i = 0; i < (int) m_capacity; i++) {
		m_ppLODObject[i] = 0;
	}
#endif
}

inline LODListBase::~LODListBase()
{
	// all LODObject* should have been popped by client
	assert(m_size == 0);

	delete[] m_ppLODObject;
}

inline size_t LODListBase::Size() const
{
	return m_size;
}

inline size_t LODListBase::Capacity() const
{
	return m_capacity;
}

inline const LODObject* LODListBase::operator[](int i) const
{
	assert((0 <= i) && (i < (int) m_size));

	return m_ppLODObject[i];
}

inline const LODObject* LODListBase::PushBack(const LODObject* pLOD)
{
	assert(m_size < m_capacity);

	m_ppLODObject[m_size++] = pLOD;
	return pLOD;
}

inline const LODObject* LODListBase::PopBack()
{
	const LODObject* pLOD;

	assert(m_size > 0);

	pLOD = m_ppLODObject[--m_size];

#ifdef _DEBUG
	m_ppLODObject[m_size] = 0;
#endif

	return pLOD;
}

#ifdef _DEBUG
inline void LODListBase::Dump(void (*pTracer)(const char*, ...)) const
{
	int i;

	pTracer("LODListBase<0x%x>: Capacity=%d, Size=%d\n", (void*) this, m_capacity, m_size);

	for (i = 0; i < (int) m_size; i++) {
		pTracer("   [%d]: LOD<0x%x>\n", i, m_ppLODObject[i]);
	}

	for (i = (int) m_size; i < (int) m_capacity; i++) {
		assert(m_ppLODObject[i] == 0);
	}
}
#endif

//////////////////////////////////////////////////////////////////////////////
//
// LODList implementation

template <class T>
inline LODList<T>::LODList(size_t capacity) : LODListBase(capacity)
{
}

template <class T>
inline const T* LODList<T>::operator[](int i) const
{
	return static_cast<const T*>(LODListBase::operator[](i));
}

template <class T>
inline const T* LODList<T>::PushBack(const T* pLOD)
{
	return static_cast<const T*>(LODListBase::PushBack(pLOD));
}

template <class T>
inline const T* LODList<T>::PopBack()
{
	return static_cast<const T*>(LODListBase::PopBack());
}

// VTABLE: LEGO1 0x100dbdc0
// class LODList<ViewLOD>

// SYNTHETIC: LEGO1 0x100a7740
// LODList<ViewLOD>::`scalar deleting destructor'

// re-enable: identifier was truncated to '255' characters in the debug information
#pragma warning(default : 4786)

#endif // LODLIST_H
