package bcs

import (
	"reflect"
	"strings"
	"sync"
	"testing"
)

type cachedPair struct {
	A uint32
	B string
}

// The plan for a type is built once and handed out by pointer afterwards. If it
// were rebuilt per call, every encode would pay for reflection again.
func TestLookupBuildsATypeOnce(t *testing.T) {
	typ := reflect.TypeOf(cachedPair{})

	first := tc.lookup(typ)
	if first.writerError != nil || first.readerError != nil {
		t.Fatalf("building %s failed: %v / %v", typ, first.writerError, first.readerError)
	}
	for range 10 {
		if again := tc.lookup(typ); again != first {
			t.Fatal("a second lookup returned a different plan")
		}
	}

	// Once published, the entry is reachable without taking the lock.
	m := tc.cur.Load()
	if m == nil {
		t.Fatal("nothing was published to the read path")
	}
	if (*m)[typ] != first {
		t.Error("the published entry is not the one lookup returned")
	}
}

// Building one type pulls in the types it is made of, and they stay cached too.
func TestBuildingATypeCachesWhatItContains(t *testing.T) {
	type inner struct {
		X uint16
	}
	type outer struct {
		In  inner
		Ptr *inner
		Lst []inner
	}

	tc.lookup(reflect.TypeOf(outer{}))

	m := tc.cur.Load()
	if m == nil {
		t.Fatal("nothing was published")
	}
	for _, typ := range []reflect.Type{
		reflect.TypeOf(inner{}),
		reflect.TypeOf(&inner{}),
		reflect.TypeOf([]inner{}),
		reflect.TypeOf(uint16(0)),
	} {
		if _, ok := (*m)[typ]; !ok {
			t.Errorf("%s was not cached alongside its parent", typ)
		}
	}
}

type selfPointer struct {
	Next *selfPointer
	V    uint8
}

type selfSlice struct {
	Kids []selfSlice
	V    uint8
}

type mutualA struct {
	B *mutualB
	V uint8
}

type mutualB struct {
	A *mutualA
	V uint8
}

// A type that contains itself has no finite encoding. resolve spots the entry
// it is already building and marks it, rather than recursing until the stack
// runs out.
func TestRecursiveTypesAreRefusedNotFollowed(t *testing.T) {
	for _, typ := range []reflect.Type{
		reflect.TypeOf(selfPointer{}),
		reflect.TypeOf(selfSlice{}),
		reflect.TypeOf(mutualA{}),
		reflect.TypeOf(mutualB{}),
	} {
		t.Run(typ.Name(), func(t *testing.T) {
			w, werr := cachedWriter(typ)
			if werr == nil {
				t.Fatal("a recursive type got a writer")
			}
			if w != nil {
				t.Error("the writer is non-nil beside an error")
			}
			if !strings.Contains(werr.Error(), "recursive type") {
				t.Errorf("error is %q, want it to say the type is recursive", werr)
			}

			r, rerr := cachedReader(typ)
			if rerr == nil {
				t.Fatal("a recursive type got a reader")
			}
			if r != nil {
				t.Error("the reader is non-nil beside an error")
			}
		})
	}
}

// A failure is a result too. Caching it keeps a bad type from re-running the
// whole reflection walk on every call.
func TestFailuresAreCachedLikeSuccesses(t *testing.T) {
	for _, typ := range []reflect.Type{
		reflect.TypeOf(int(0)),
		reflect.TypeOf(float64(0)),
		reflect.TypeOf(map[string]uint8{}),
		reflect.TypeOf(make(chan int)),
	} {
		t.Run(typ.Kind().String(), func(t *testing.T) {
			first := tc.lookup(typ)
			if first.writerError == nil || first.readerError == nil {
				t.Fatalf("%s was given an encoding", typ)
			}
			if again := tc.lookup(typ); again != first {
				t.Error("the failure was recomputed rather than cached")
			}

			_, err := cachedWriter(typ)
			if err == nil || !strings.Contains(err.Error(), "no encoding") {
				t.Errorf("cachedWriter error is %v", err)
			}
		})
	}
}

type conc0 struct{ A uint8 }
type conc1 struct{ A uint16 }
type conc2 struct{ A uint32 }
type conc3 struct{ A uint64 }
type conc4 struct{ A string }
type conc5 struct{ A []uint8 }
type conc6 struct{ A [4]uint32 }
type conc7 struct{ A *uint8 }

// build takes a lock and swaps a whole map, so racing callers must still each
// come away with one consistent plan per type.
func TestConcurrentLookupsAgree(t *testing.T) {
	types := []reflect.Type{
		reflect.TypeOf(conc0{}), reflect.TypeOf(conc1{}),
		reflect.TypeOf(conc2{}), reflect.TypeOf(conc3{}),
		reflect.TypeOf(conc4{}), reflect.TypeOf(conc5{}),
		reflect.TypeOf(conc6{}), reflect.TypeOf(conc7{}),
	}

	var (
		mu    sync.Mutex
		seen  = map[reflect.Type]*typeInfo{}
		wg    sync.WaitGroup
		start = make(chan struct{})
	)
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for _, typ := range types {
				c := tc.lookup(typ)
				if c.writerError != nil {
					t.Errorf("%s failed to build: %v", typ, c.writerError)

					return
				}
				mu.Lock()
				if prev, ok := seen[typ]; ok && prev != c {
					t.Errorf("%s resolved to two different plans", typ)
				} else {
					seen[typ] = c
				}
				mu.Unlock()
			}
		}()
	}
	close(start)
	wg.Wait()

	m := tc.cur.Load()
	for _, typ := range types {
		if _, ok := (*m)[typ]; !ok {
			t.Errorf("%s was lost from the published map", typ)
		}
	}
}

// build re-checks the published map after taking the lock, because another
// goroutine may have finished the same type while this one waited. Calling
// build on a type that is already published walks that branch without having
// to win a race for it.
func TestBuildRechecksAfterTakingTheLock(t *testing.T) {
	typ := reflect.TypeOf(cachedPair{})
	published := tc.lookup(typ)

	if again := tc.build(typ); again != published {
		t.Error("build made a second plan for a type that was already published")
	}
}
