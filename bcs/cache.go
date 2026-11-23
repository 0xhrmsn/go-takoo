package bcs
import (
	"fmt"
	"maps"
	"reflect"
	"sync"
	"sync/atomic"
)

// typeInfo is everything the codec worked out about one type: how to write it,
// how to read it, or why it cannot be either. A failure is kept alongside the
// successes so a bad type is diagnosed once rather than on every call.
type typeInfo struct {
	writer      funcWriter
	writerError error
	reader      funcReader
	readerError error
}

func (ti *typeInfo) generate(typ reflect.Type) *typeInfo {
	ti.writer, ti.writerError = makeWriter(typ)
	ti.reader, ti.readerError = makeReader(typ)
	return ti
}

// typeCache holds those plans, so reflection is paid for once per type instead
// of once per value. Readers take cur without a lock; a writer builds a whole
// new map under mu and swaps it in, which keeps the common path free of
// contention at the cost of copying the map when a new type turns up.
//
// next is the map being built. It is live only for the span of one build, and
// it is what lets a type under construction be found again when it refers to
// itself.
type typeCache struct {
	cur  atomic.Pointer[map[reflect.Type]*typeInfo]
	mu   sync.Mutex
	next map[reflect.Type]*typeInfo
}

var tc typeCache

func (tc *typeCache) lookup(typ reflect.Type) *typeInfo {
	if m := tc.cur.Load(); m != nil {
		if c, ok := (*m)[typ]; ok {
			return c
		}
	}
	return tc.build(typ)
}

// build plans a type and everything it is made of, then publishes them together.
func (tc *typeCache) build(typ reflect.Type) *typeInfo {
	tc.mu.Lock()
	defer tc.mu.Unlock()

	staging := map[reflect.Type]*typeInfo{}
	if m := tc.cur.Load(); m != nil {
		// Another goroutine may have finished this very type while this one
		// waited for the lock.
		if c, ok := (*m)[typ]; ok {
			return c
		}
		staging = maps.Clone(*m)
	}

	// Plans land in staging, where resolve can find them, and only reach the
	// read path once the whole walk is done.
	tc.next = staging
	c := tc.resolve(typ)
	tc.cur.Store(&staging)
	tc.next = nil
	return c
}

// resolve returns the plan for one type, building it if this is the first time
// the walk has reached it.
func (tc *typeCache) resolve(typ reflect.Type) *typeInfo {
	if c, ok := tc.next[typ]; ok {
		// Reached again while it is still being built, so the type contains
		// itself: there is no finite encoding, and following it would run the
		// stack out instead of saying so.
		if c.writer == nil && c.writerError == nil {
			c.writerError = fmt.Errorf("utils/encoding: recursive type: %s", typ)
			c.readerError = c.writerError
		}
		return c
	}

	// Recorded before generate runs, so the check above has something to find.
	c := new(typeInfo)
	tc.next[typ] = c
	return c.generate(typ)
}

func cachedWriter(typ reflect.Type) (funcWriter, error) {
	c := tc.lookup(typ)
	return c.writer, c.writerError
}

func cachedReader(typ reflect.Type) (funcReader, error) {
	c := tc.lookup(typ)
	return c.reader, c.readerError
}
