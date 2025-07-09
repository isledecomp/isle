#ifndef MXHASHTABLE_H
#define MXHASHTABLE_H

#include "mxcollection.h"
#include "mxcore.h"
#include "mxtypes.h"

#define HASH_TABLE_INIT_SIZE 128

template <class T>
class MxHashTableCursor;

template <class T>
class MxHashTableNode {
public:
	MxHashTableNode(T p_obj, MxU32 p_hash, MxHashTableNode* p_prev, MxHashTableNode* p_next)
	{
		m_obj = p_obj;
		m_hash = p_hash;
		m_prev = p_prev;
		m_next = p_next;
	}

	// DECOMP: Should use getter and setter methods here per the style guide.
	// However, LEGO1D (with no functions inlined) does not use them.
	T m_obj;
	MxU32 m_hash;
	MxHashTableNode* m_prev;
	MxHashTableNode* m_next;
};

template <class T>
class MxHashTable : protected MxCollection<T> {
public:
	enum Option {
		e_noExpand = 0,
		e_expandAll,
		e_expandMultiply,
	};

	MxHashTable()
	{
		m_numSlots = HASH_TABLE_INIT_SIZE;
		MxU32 unused = 0;
		m_slots = new MxHashTableNode<T>*[m_numSlots];
		memset(m_slots, 0, sizeof(MxHashTableNode<T>*) * m_numSlots);
		m_resizeOption = e_noExpand;
	}

	~MxHashTable() override;

	void Resize();
	void Add(T);
	void DeleteAll();

	virtual MxU32 Hash(T) { return 0; }

	friend class MxHashTableCursor<T>;

protected:
	void NodeInsert(MxHashTableNode<T>*);

	MxHashTableNode<T>** m_slots; // 0x10
	MxU32 m_numSlots;             // 0x14
	MxU32 m_autoResizeRatio;      // 0x18
	Option m_resizeOption;        // 0x1c
	// FIXME: or FIXME? This qword is used as an integer or double depending
	// on the value of m_resizeOption. Hard to say whether this is how the devs
	// did it, but a simple cast in either direction doesn't match.
	union {
		MxU32 m_increaseAmount;  // 0x20
		double m_increaseFactor; // 0x20
	};
};

template <class T>
class MxHashTableCursor : public MxCore {
public:
	MxHashTableCursor(MxHashTable<T>* p_table)
	{
		m_table = p_table;
		m_match = NULL;
	}

	MxBool Find(T p_obj);
	MxBool Current(T& p_obj);
	void DeleteMatch();

private:
	MxHashTable<T>* m_table;
	MxHashTableNode<T>* m_match;
};

template <class T>
MxBool MxHashTableCursor<T>::Find(T p_obj)
{
	MxU32 hash = m_table->Hash(p_obj);

	for (MxHashTableNode<T>* t = m_table->m_slots[hash % m_table->m_numSlots]; t; t = t->m_next) {
		if (t->m_hash == hash && !m_table->Compare(t->m_obj, p_obj)) {
			m_match = t;
		}
	}

	return m_match != NULL;
}

template <class T>
MxBool MxHashTableCursor<T>::Current(T& p_obj)
{
	if (m_match) {
		p_obj = m_match->m_obj;
	}

	return m_match != NULL;
}

template <class T>
void MxHashTableCursor<T>::DeleteMatch()
{
	// Cut the matching node out of the linked list
	// by updating pointer references.
	if (m_match) {
		if (m_match->m_prev) {
			m_match->m_prev->m_next = m_match->m_next;
		}
		else {
			// No "prev" node, so move "next" to the head of the list.
			m_table->m_slots[m_match->m_hash % m_table->m_numSlots] = m_match->m_next;
		}

		if (m_match->m_next) {
			m_match->m_next->m_prev = m_match->m_prev;
		}

		m_table->m_customDestructor(m_match->m_obj);
		delete m_match;
		m_table->m_count--;
	}
}

template <class T>
MxHashTable<T>::~MxHashTable()
{
	DeleteAll();
	delete[] m_slots;
}

template <class T>
void MxHashTable<T>::DeleteAll()
{
	for (MxS32 i = 0; i < m_numSlots; i++) {
		MxHashTableNode<T>* next;
		for (MxHashTableNode<T>* t = m_slots[i]; t != NULL; t = next) {
			next = t->m_next;
			this->m_customDestructor(t->m_obj);
			delete t;
		}
	}

	this->m_count = 0;
	memset(m_slots, 0, sizeof(MxHashTableNode<T>*) * m_numSlots);
}

template <class T>
inline void MxHashTable<T>::Resize()
{
	// Save a reference to the current table
	// so we can walk nodes and re-insert
	MxU32 oldSize = m_numSlots;
	MxHashTableNode<T>** oldTable = m_slots;

	switch (m_resizeOption) {
	case e_expandAll:
		m_numSlots += m_increaseAmount;
		break;
	case e_expandMultiply:
		m_numSlots *= m_increaseFactor;
		break;
	}

	MxU32 unused = 0;
	m_slots = new MxHashTableNode<T>*[m_numSlots];
	memset(m_slots, 0, sizeof(MxHashTableNode<T>*) * m_numSlots);
	this->m_count = 0;

	for (MxS32 i = 0; i < oldSize; i++) {
		MxHashTableNode<T>* next;
		for (MxHashTableNode<T>* t = oldTable[i]; t != NULL; t = next) {
			next = t->m_next;
			NodeInsert(t);
		}
	}

	delete[] oldTable;
}

template <class T>
inline void MxHashTable<T>::NodeInsert(MxHashTableNode<T>* p_node)
{
	MxS32 bucket = p_node->m_hash % m_numSlots;

	p_node->m_next = m_slots[bucket];

	if (m_slots[bucket]) {
		m_slots[bucket]->m_prev = p_node;
	}

	m_slots[bucket] = p_node;
	this->m_count++;
}

template <class T>
inline void MxHashTable<T>::Add(T p_newobj)
{
	if (m_resizeOption && ((this->m_count + 1) / m_numSlots) > m_autoResizeRatio) {
		MxHashTable<T>::Resize();
	}

	MxU32 hash = Hash(p_newobj);
	MxU32 unused = 0;

	MxHashTableNode<T>* node = new MxHashTableNode<T>(p_newobj, hash, NULL, NULL);

	MxHashTable<T>::NodeInsert(node);
}

#undef HASH_TABLE_INIT_SIZE

#endif // MXHASHTABLE_H
