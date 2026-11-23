// Command go-takoo runs a committee of validators in one process, so the
// consensus engine can be watched doing its job before there is a network, a
// mempool, or a state layer to plug it into.
//
// Everything outside consensus is faked here: the payload is a counter, the
// "execution" is a hash, safety data lives in memory, and the network is a map
// of engines. What is real is the part being tested -- the rounds, the votes,
// the certificates, and the commit rule.
//
//	go run ./cmd -n 4 -blocks 10
//	go run ./cmd -n 7 -dead 1        # leader of round 1 never answers
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"time"

	"go-takoo/consensus"
	"go-takoo/crypto"
	"go-takoo/crypto/bls12381"
)

func main() {
	size := flag.Int("n", 4, "committee size")
	blocks := flag.Int("blocks", 10, "stop after this many committed blocks")
	dead := flag.Int("dead", -1, "index of a validator that answers nothing")
	base := flag.Duration("timeout", 500*time.Millisecond, "how long a round waits before it is given up on")
	flag.Parse()

	if err := run(*size, *blocks, *dead, *base); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(size, blocks, dead int, base time.Duration) error {
	if size < 4 {
		return fmt.Errorf("a committee needs at least 4 members to tolerate one failure")
	}

	cluster := &cluster{engines: make([]*consensus.Engine, size), dead: dead}
	members := make([]consensus.Member, size)
	keys := make([]*bls12381.PrivateKey, size)
	for i := range size {
		seed := make([]byte, 32)
		seed[0], seed[1] = byte(i+1), byte(i>>8)
		key, err := bls12381.PrivateKeyFromSeed(seed)
		if err != nil {
			return err
		}
		keys[i] = key
		members[i] = consensus.Member{PublicKey: key.Public(), Stake: 1}
	}

	committee, err := consensus.NewCommittee(1, members)
	if err != nil {
		return err
	}
	genesis := consensus.BlockRef{Epoch: 1, ID: crypto.Hash256([]byte("go-takoo genesis"))}

	for i := range size {
		safety, err := consensus.NewSafetyRules(keys[i], &memory{})
		if err != nil {
			return err
		}
		engine, err := consensus.New(consensus.Config{
			ID:              uint16(i),
			Epoch:           1,
			Genesis:         genesis,
			Base:            base,
			Maximum:         10 * time.Second,
			MaxPayloadBytes: 1 << 20,
			Now:             time.Now,
		}, committee, safety, consensus.Deps{
			Execution: execution{},
			Payload:   payload{},
			Store:     &memory{},
			Network:   &network{self: uint16(i), cluster: cluster},
		})
		if err != nil {
			return err
		}
		cluster.engines[i] = engine
	}

	fmt.Printf("committee of %d, quorum %d stake, round timeout %s\n", size, committee.Threshold(), base)
	if dead >= 0 {
		fmt.Printf("validator %d is dead: every round it leads has to time out\n", dead)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	for _, engine := range cluster.engines {
		go engine.Start(ctx)
	}

	// The engines have no clock of their own: they are told what time it is,
	// which is what lets a test replace time entirely.
	ticker := time.NewTicker(base / 4)
	defer ticker.Stop()
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-ticker.C:
				for _, engine := range cluster.engines {
					engine.Tick(now)
				}
			}
		}
	}()

	started, last := time.Now(), time.Now()
	for committed := 0; committed < blocks; committed++ {
		select {
		case <-ctx.Done():
			return nil
		case ref := <-cluster.engines[0].Committed():
			fmt.Printf("committed round %-4d %x  (+%s)\n", ref.Round, ref.ID[:6], time.Since(last).Round(time.Millisecond))
			last = time.Now()
		}
	}

	fmt.Printf("%d blocks in %s\n", blocks, time.Since(started).Round(time.Millisecond))

	return nil
}

// memory is the safety store a real validator would keep on disk. Holding it in
// memory is fine here and wrong in production: a validator that forgets which
// round it voted in will vote twice after a restart.
type memory struct {
	mu                             sync.Mutex
	lastVotedRound, preferredRound uint64
}

func (m *memory) SaveSafety(lastVoted, preferred uint64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.lastVotedRound, m.preferredRound = lastVoted, preferred

	return nil
}

func (m *memory) LoadSafety() (uint64, uint64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	return m.lastVotedRound, m.preferredRound, nil
}

// payload stands in for the mempool: consensus only ever sees bytes.
type payload struct{ n int }

func (p payload) Pull(int) ([]byte, error) { return fmt.Appendf(nil, "block payload %d", p.n), nil }

func (payload) Check([]byte) error { return nil }

// execution stands in for the state layer: a digest is all consensus wants
// back, and it never looks inside it.
type execution struct{}

func (execution) Execute(ref consensus.BlockRef, data []byte) (crypto.Hash, error) {
	return crypto.MultiHash256(ref.ID[:], data), nil
}

// cluster is the world the engines live in.
type cluster struct {
	engines []*consensus.Engine
	dead    int
}

// network hands messages to the other engines directly. A real one would
// serialise, send, and lose some of them; this one loses only what the dead
// validator would have carried.
type network struct {
	self    uint16
	cluster *cluster
}

func (n *network) Broadcast(msg []byte) error {
	for i := range n.cluster.engines {
		if uint16(i) != n.self {
			n.deliver(uint16(i), msg)
		}
	}

	return nil
}

func (n *network) Send(to uint16, msg []byte) error {
	n.deliver(to, msg)

	return nil
}

func (n *network) deliver(to uint16, msg []byte) {
	if int(n.self) == n.cluster.dead || int(to) == n.cluster.dead {
		return
	}
	message, err := consensus.Decode(msg)
	if err != nil {
		return
	}
	n.cluster.engines[to].Submit(message)
}
