package table

import (
	"bytes"
	"math/rand"
	"time"

	"github.com/cespare/xxhash"
	"github.com/named-data/YaNFD/core"
	"github.com/named-data/YaNFD/ndn"
)

// PitCsTree represents a PIT-CS implementation that uses a name tree
type PitCsTree struct {
	BasePitCsTable

	root *pitCsTreeNode

	nPitEntries int
	pitTokenMap map[uint32]*nameTreePitEntry

	nCsEntries    int
	csReplacement CsReplacementPolicy
	csMap         map[uint64]*nameTreeCsEntry
}

type nameTreePitEntry struct {
	basePitEntry                // compose with BasePitEntry
	pitCsTable   *PitCsTree     // pointer to tree
	node         *pitCsTreeNode // the tree node associated with this entry
}

type nameTreeCsEntry struct {
	baseCsEntry                // compose with BasePitEntry
	node        *pitCsTreeNode // the tree node associated with this entry
}

// pitCsTreeNode represents an entry in a PIT-CS tree.
type pitCsTreeNode struct {
	component ndn.NameComponent
	depth     int

	parent   *pitCsTreeNode
	children []*pitCsTreeNode

	pitEntries []*nameTreePitEntry

	csEntry *nameTreeCsEntry
}

// NewPitCS creates a new combined PIT-CS for a forwarding thread.
func NewPitCS() *PitCsTree {
	pitCs := new(PitCsTree)
	pitCs.root = new(pitCsTreeNode)
	pitCs.root.component = nil // Root component will be nil since it represents zero components
	pitCs.root.pitEntries = make([]*nameTreePitEntry, 0)
	pitCs.expiringPitEntries = make(chan PitEntry, tableQueueSize)
	pitCs.pitTokenMap = make(map[uint32]*nameTreePitEntry)

	// This value has already been validated from loading the configuration, so we know it will be one of the following (or else fatal)
	switch csReplacementPolicy {
	case "lru":
		pitCs.csReplacement = NewCsLRU(pitCs) // TODO: this will be fixed once implementation is done
	default:
		core.LogFatal(pitCs, "Unknown CS replacement policy ", csReplacementPolicy)
	}
	pitCs.csMap = make(map[uint64]*nameTreeCsEntry)

	return pitCs
}

func (e *nameTreePitEntry) PitCs() PitCsTable {
	return e.pitCsTable
}

// FindOrInsertPIT inserts an entry in the PIT upon receipt of an Interest. Returns tuple of PIT entry and whether the Nonce is a duplicate.
// Originally implemented as FindOrInsertPIT()
func (p *PitCsTree) InsertInterest(interest *ndn.Interest, hint *ndn.Name, inFace uint64) (PitEntry, bool) {
	node := p.root.fillTreeToPrefix(interest.Name())

	var entry *nameTreePitEntry
	for _, curEntry := range node.pitEntries {
		if curEntry.CanBePrefix() == interest.CanBePrefix() && curEntry.MustBeFresh() == interest.MustBeFresh() && ((hint == nil && curEntry.ForwardingHint == nil) || hint.Equals(curEntry.ForwardingHint())) {
			entry = curEntry
			break
		}
	}

	if entry == nil {
		p.nPitEntries++
		entry = new(nameTreePitEntry)
		entry.node = node
		entry.pitCsTable = p
		entry.name = interest.Name()
		entry.canBePrefix = interest.CanBePrefix()
		entry.mustBeFresh = interest.MustBeFresh()
		entry.forwardingHint = hint
		entry.inRecords = make(map[uint64]*PitInRecord)
		entry.outRecords = make(map[uint64]*PitOutRecord)
		entry.satisfied = false
		node.pitEntries = append(node.pitEntries, entry)
		entry.token = p.generateNewPitToken()
		p.pitTokenMap[entry.token] = entry
	}

	for face, inRecord := range entry.inRecords {
		// Only considered a duplicate (loop) if from different face since is just retransmission and not loop if same face
		if face != inFace && bytes.Equal(inRecord.LatestNonce, interest.Nonce()) {
			return entry, true
		}
	}

	// Cancel expiration time
	entry.expirationTime = time.Unix(0, 0)

	return entry, false
}

// RemovePITEntry removes the specified PIT entry.
// Originally implemented as RemovePITEntry()
func (p *PitCsTree) RemoveInterest(pitEntry PitEntry) bool {
	e := pitEntry.(*nameTreePitEntry)
	for i, entry := range e.node.pitEntries {
		if entry == pitEntry {
			if i < len(e.node.pitEntries)-1 {
				copy(e.node.pitEntries[i:], e.node.pitEntries[i+1:])
			}
			e.node.pitEntries = e.node.pitEntries[:len(e.node.pitEntries)-1]
			if len(e.node.pitEntries) == 0 {
				entry.node.pruneIfEmpty()
			}
			p.nPitEntries--
			return true
		}
	}
	return false
}

// Originally implemented as FindOrInsertPIT()
func (p *PitCsTree) FindInterestExactMatch(interest *ndn.Interest) PitEntry {
	node := p.root.findExactMatchEntry(interest.Name())
	for _, curEntry := range node.pitEntries {
		if curEntry.CanBePrefix() == interest.CanBePrefix() && curEntry.MustBeFresh() == interest.MustBeFresh() {
			return curEntry
		}
	}
	return nil
}

// Logic taken from FindPITFromData
func (p *PitCsTree) FindInterestPrefixMatch(interest *ndn.Interest, token uint32) []PitEntry {
	matching := make([]PitEntry, 0)
	dataNameLen := interest.Name().Size()
	for curNode := p.root.findLongestPrefixEntry(interest.Name()); curNode != nil; curNode = curNode.parent {
		for _, entry := range curNode.pitEntries {
			if entry.canBePrefix || curNode.depth == dataNameLen {
				matching = append(matching, entry)
			}
		}
	}
	return matching
}

func (p *PitCsTree) FindInterestPrefixMatchByData(data *ndn.Data, token *uint32) []PitEntry {
	if token != nil {
		if entry, ok := p.pitTokenMap[*token]; ok && entry.Token() == *token {
			return []PitEntry{entry}
		}
		return nil
	}

	matching := make([]PitEntry, 0)
	dataNameLen := data.Name().Size()
	for curNode := p.root.findLongestPrefixEntry(data.Name()); curNode != nil; curNode = curNode.parent {
		for _, entry := range curNode.pitEntries {
			if entry.CanBePrefix() || curNode.depth == dataNameLen {
				matching = append(matching, entry)
			}
		}
	}
	return matching
}

// PitSize returns the number of entries in the PIT.
func (p *PitCsTree) PitSize() int {
	return p.nPitEntries
}

// CsSize returns the number of entries in the CS.
func (p *PitCsTree) CsSize() int {
	return p.nCsEntries
}

// IsCsAdmitting returns whether the CS is admitting contents.
func (p *PitCsTree) IsCsAdmitting() bool {
	return csAdmit
}

// IsCsServing returns whether the CS is serving contents.
func (p *PitCsTree) IsCsServing() bool {
	return csServe
}

// Originally implemented as FindOrInsertOutRecord()
func (e *nameTreePitEntry) InsertOutRecord(interest *ndn.Interest, face uint64) *PitOutRecord {
	var record *PitOutRecord
	var ok bool
	if record, ok = e.outRecords[face]; !ok {
		record := new(PitOutRecord)
		record.Face = face
		record.LatestNonce = interest.Nonce()
		record.LatestTimestamp = time.Now()
		record.LatestInterest = interest
		record.ExpirationTime = time.Now().Add(interest.Lifetime())
		e.outRecords[face] = record
		return record
	}

	// Existing record
	record.LatestNonce = interest.Nonce()
	record.LatestTimestamp = time.Now()
	record.LatestInterest = interest
	record.ExpirationTime = time.Now().Add(interest.Lifetime())
	return record
}

// Originally implemented as FindOrInsertOutRecord()
func (e *nameTreePitEntry) GetOutRecords() []*PitOutRecord {
	records := make([]*PitOutRecord, 0)
	for _, value := range e.outRecords {
		records = append(records, value)
	}
	return records
}

func (p *pitCsTreeNode) findExactMatchEntry(name *ndn.Name) *pitCsTreeNode {
	if name.Size() > p.depth {
		for _, child := range p.children {
			if name.At(child.depth - 1).Equals(child.component) {
				return child.findExactMatchEntry(name)
			}
		}
	} else if name.Size() == p.depth {
		return p
	}
	return nil
}

func (p *pitCsTreeNode) findLongestPrefixEntry(name *ndn.Name) *pitCsTreeNode {
	if name.Size() > p.depth {
		for _, child := range p.children {
			if name.At(child.depth - 1).Equals(child.component) {
				return child.findLongestPrefixEntry(name)
			}
		}
	}
	return p
}

func (p *pitCsTreeNode) fillTreeToPrefix(name *ndn.Name) *pitCsTreeNode {
	curNode := p.findLongestPrefixEntry(name)
	for depth := curNode.depth + 1; depth <= name.Size(); depth++ {
		newNode := new(pitCsTreeNode)
		newNode.component = name.At(depth - 1).DeepCopy()
		newNode.depth = depth
		newNode.parent = curNode
		curNode.children = append(curNode.children, newNode)
		curNode = newNode
	}
	return curNode
}

func (p *pitCsTreeNode) pruneIfEmpty() {
	for curNode := p; curNode.parent != nil && len(curNode.children) == 0 && len(curNode.pitEntries) == 0 && curNode.csEntry == nil; curNode = curNode.parent {
		// Remove from parent's children
		for i, child := range curNode.parent.children {
			if child == p {
				if i < len(curNode.parent.children)-1 {
					copy(curNode.parent.children[i:], curNode.parent.children[i+1:])
				}
				curNode.parent.children = curNode.parent.children[:len(curNode.parent.children)-1]
				break
			}
		}
	}
}

func (p *PitCsTree) generateNewPitToken() uint32 {
	for {
		token := rand.Uint32()
		if _, ok := p.pitTokenMap[token]; !ok {
			return token
		}
	}
}

func (p *PitCsTree) hashCsName(name *ndn.Name) uint64 {
	return xxhash.Sum64String(name.String())
}

// FindDataExactMatch finds an exact matching entry in the CS (if any). If MustBeFresh is set to true in the Interest, only non-stale CS entries will be returned.
// Originally implemented as FindMatchingDataCS()
func (p *PitCsTree) FindDataExactMatch(interest *ndn.Interest) CsEntry {
	node := p.root.findExactMatchEntry(interest.Name())
	if node != nil {
		if !interest.CanBePrefix() {
			if node.csEntry != nil {
				p.csReplacement.BeforeUse(node.csEntry.index, node.csEntry.data)
			}
			return node.csEntry
		}
		return node.findMatchingDataCSPrefix(interest) // TODO: is this a bug?
		// Shouldn't we call this if node == nil, not if node != nil?
	}
	return nil
}

// Originally implemented as FindMatchingDataCS()
func (p *PitCsTree) FindDataPrefixMatch(interest *ndn.Interest) CsEntry {
	if interest.CanBePrefix() {
		return p.root.findMatchingDataCSPrefix(interest)
	}
	return nil
}

// InsertData inserts a Data packet into the Content Store.
// Originally implemented as InsertDataCS
func (p *PitCsTree) InsertData(data *ndn.Data) {
	index := p.hashCsName(data.Name())

	if entry, ok := p.csMap[index]; ok {
		// Replace existing entry
		entry.data = data

		if data.MetaInfo() == nil || data.MetaInfo().FinalBlockID() == nil {
			entry.staleTime = time.Now()
		} else {
			entry.staleTime = time.Now().Add(*data.MetaInfo().FreshnessPeriod())
		}

		p.csReplacement.AfterRefresh(index, data)
	} else {
		// New entry
		p.nCsEntries++
		node := p.root.fillTreeToPrefix(data.Name())
		node.csEntry = new(nameTreeCsEntry)
		node.csEntry.node = node
		node.csEntry.index = index
		node.csEntry.data = data
		p.csMap[index] = node.csEntry
		p.csReplacement.AfterInsert(index, data)

		// Tell replacement strategy to evict entries if needed
		p.csReplacement.EvictEntries()
	}
}

// eraseCsDataFromReplacementStrategy allows the replacement strategy to erase the data with the specified name from the Content Store.
func (p *PitCsTree) eraseCsDataFromReplacementStrategy(index uint64) {
	if entry, ok := p.csMap[index]; ok {
		entry.node.csEntry = nil
		delete(p.csMap, index)
		p.nCsEntries--
	}
}

func (p *pitCsTreeNode) findMatchingDataCSPrefix(interest *ndn.Interest) CsEntry {
	if p.csEntry != nil && (!interest.MustBeFresh() || time.Now().Before(p.csEntry.staleTime)) {
		return p.csEntry
	}

	if p.depth < interest.Name().Size() {
		for _, child := range p.children {
			if interest.Name().At(p.depth).Equals(child.component) {
				return child.findMatchingDataCSPrefix(interest)
			}
		}
	}

	// If found none, then return
	return nil
}
