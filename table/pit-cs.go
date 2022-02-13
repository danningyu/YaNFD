/* YaNFD - Yet another NDN Forwarding Daemon
 *
 * Copyright (C) 2020-2021 Eric Newberry.
 *
 * This file is licensed under the terms of the MIT License, as found in LICENSE.md.
 */

package table

import (
	"time"

	"github.com/named-data/YaNFD/ndn"
)

// PitEntry is an entry in a thread's PIT.
type PitEntry interface {
	PitCs() PitCsTable
	Name() *ndn.Name // external users can access this
	CanBePrefix() bool
	MustBeFresh() bool
	ForwardingHint() *ndn.Name
	// Interests must match in terms of Forwarding Hint to be
	// aggregated in PIT.
	InRecords() map[uint64]*PitInRecord   // Key is face ID
	OutRecords() map[uint64]*PitOutRecord // Key is face ID
	ExpirationTime() time.Time
	SetExpirationTime(t time.Time)
	Satisfied() bool
	SetSatisfied(isSatisfied bool)

	Token() uint32

	InsertInRecord(interest *ndn.Interest, face uint64, incomingPitToken []byte) (*PitInRecord, bool)
	InsertOutRecord(interest *ndn.Interest, face uint64) *PitOutRecord

	GetOutRecords() []*PitOutRecord
	ClearOutRecords()
	ClearInRecords()
}

type BasePitEntry struct {
	// lowercase fields so that they aren't exported
	name           *ndn.Name
	canBePrefix    bool
	mustBeFresh    bool
	forwardingHint *ndn.Name
	// Interests must match in terms of Forwarding Hint to be
	// aggregated in PIT.
	inRecords      map[uint64]*PitInRecord  // Key is face ID
	outRecords     map[uint64]*PitOutRecord // Key is face ID
	expirationTime time.Time
	satisfied      bool

	token uint32
}

// FindOrInsertInRecord finds or inserts an InRecord for the face, updating the metadata and returning whether there was already an in-record in the entry.
func (bpe *BasePitEntry) InsertInRecord(interest *ndn.Interest, face uint64, incomingPitToken []byte) (*PitInRecord, bool) {
	var record *PitInRecord
	var ok bool
	if record, ok = bpe.inRecords[face]; !ok {
		record := new(PitInRecord)
		record.Face = face
		record.LatestNonce = interest.Nonce()
		record.LatestTimestamp = time.Now()
		record.LatestInterest = interest
		record.ExpirationTime = time.Now().Add(interest.Lifetime())
		record.PitToken = incomingPitToken
		bpe.inRecords[face] = record
		return record, len(bpe.inRecords) > 1
	}

	// Existing record
	record.LatestNonce = interest.Nonce()
	record.LatestTimestamp = time.Now()
	record.LatestInterest = interest
	record.ExpirationTime = time.Now().Add(interest.Lifetime())
	return record, true
}

// ClearInRecords removes all in-records from the PIT entry.
func (e *BasePitEntry) ClearInRecords() {
	e.inRecords = make(map[uint64]*PitInRecord)
}

// ClearOutRecords removes all out-records from the PIT entry.
func (e *BasePitEntry) ClearOutRecords() {
	e.outRecords = make(map[uint64]*PitOutRecord)
}

func (bpe *BasePitEntry) Name() *ndn.Name {
	return bpe.name
}

func (bpe *BasePitEntry) CanBePrefix() bool {
	return bpe.canBePrefix
}

func (bpe *BasePitEntry) MustBeFresh() bool {
	return bpe.mustBeFresh
}

func (bpe *BasePitEntry) ForwardingHint() *ndn.Name {
	return bpe.forwardingHint
}

func (bpe *BasePitEntry) InRecords() map[uint64]*PitInRecord {
	return bpe.inRecords
}

func (bpe *BasePitEntry) OutRecords() map[uint64]*PitOutRecord {
	return bpe.outRecords
}

func (bpe *BasePitEntry) ExpirationTime() time.Time {
	return bpe.expirationTime
}

func (bpe *BasePitEntry) SetExpirationTime(t time.Time) {
	bpe.expirationTime = t
}

func (bpe *BasePitEntry) Satisfied() bool {
	return bpe.satisfied
}

func (bpe *BasePitEntry) SetSatisfied(isSatisfied bool) {
	bpe.satisfied = isSatisfied
}

func (bpe *BasePitEntry) Token() uint32 {
	return bpe.token
}

// PitInRecord records an incoming Interest on a given face.
type PitInRecord struct {
	Face            uint64
	LatestNonce     []byte
	LatestTimestamp time.Time
	LatestInterest  *ndn.Interest
	ExpirationTime  time.Time
	PitToken        []byte
}

// PitOutRecord records an outgoing Interest on a given face.
type PitOutRecord struct {
	Face            uint64
	LatestNonce     []byte
	LatestTimestamp time.Time
	LatestInterest  *ndn.Interest
	ExpirationTime  time.Time
}

// CsEntry is an entry in a thread's CS.
type CsEntry interface {
	Index() uint64 // the hash of the entry, for fast lookup
	StaleTime() time.Time
	Data() *ndn.Data
}

type BaseCsEntry struct {
	index     uint64
	staleTime time.Time
	data      *ndn.Data
}

func (bce *BaseCsEntry) Index() uint64 {
	return bce.index
}

func (bce *BaseCsEntry) StaleTime() time.Time {
	return bce.staleTime
}

func (bce *BaseCsEntry) Data() *ndn.Data {
	return bce.data
}

type PitCsTable interface {
	InsertInterest(interest *ndn.Interest, hint *ndn.Name, inFace uint64) (PitEntry, bool)
	RemoveInterest(pitEntry PitEntry) bool
	// RemoveInterestByName(name *ndn.Name)
	FindInterestExactMatch(interest *ndn.Interest) PitEntry
	// FindInterestExactMatchByName(name *ndn.Name) *PitEntry
	FindInterestPrefixMatch(interest *ndn.Interest, token uint32) []PitEntry
	FindInterestPrefixMatchByData(data *ndn.Data, token *uint32) []PitEntry
	// FindInterestPrefixMatchByName(me *ndn.Name) []*PitEntry

	PitSize() int

	// InsertOutRecord(interest *ndn.Interest, face uint64) *PitOutRecord
	// GetOutRecords(interest *ndn.Interest) []*PitOutRecord
	// GetOutRecordsByName(name *ndn.Name) []*PitOutRecord

	InsertData(data *ndn.Data)
	FindDataExactMatch(interest *ndn.Interest) CsEntry
	FindDataPrefixMatch(interest *ndn.Interest) CsEntry
	CsSize() int
	IsCsAdmitting() bool
	IsCsServing() bool

	ExpiringPitEntries() chan PitEntry
}

type BasePitCsTable struct {
	expiringPitEntries chan PitEntry
}

func (p *BasePitCsTable) ExpiringPitEntries() chan PitEntry {
	return p.expiringPitEntries
}

// SetExpirationTimerToNow updates the expiration timer to the current time.
func SetExpirationTimerToNow(e PitEntry) {
	e.SetExpirationTime(time.Now())
	e.PitCs().ExpiringPitEntries() <- e
}

// UpdateExpirationTimer updates the expiration timer to the latest expiration time of any in or out record in the entry.
func UpdateExpirationTimer(e PitEntry) {
	e.SetExpirationTime((time.Unix(0, 0)))

	for _, record := range e.InRecords() {
		if record.ExpirationTime.After(e.ExpirationTime()) {
			e.SetExpirationTime(record.ExpirationTime)
		}
	}

	for _, record := range e.OutRecords() {
		if record.ExpirationTime.After(e.ExpirationTime()) {
			e.SetExpirationTime(record.ExpirationTime)
		}
	}

	go waitForPitExpiry(e)
}

func waitForPitExpiry(e PitEntry) {
	if !e.ExpirationTime().IsZero() {
		time.Sleep(e.ExpirationTime().Sub(time.Now().Add(time.Millisecond * 1))) // Add 1 millisecond to ensure *after* expiration
		if e.ExpirationTime().Before(time.Now()) {
			// Otherwise, has been updated by another PIT entry
			e.PitCs().ExpiringPitEntries() <- e
		}
	}
}
