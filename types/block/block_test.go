package block

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"

	"go-takoo/crypto"
	"go-takoo/encoding"
	"go-takoo/types/amount"
	"go-takoo/types/transaction"
	"go-takoo/types/transaction/object"
)

func addr(n byte) crypto.Address { return crypto.Address{n} }

func tx(n byte) *transaction.Transaction {
	return &transaction.Transaction{
		Version: transaction.FormatVersion,
		ChainID: 1,
		Inputs:  []object.Ref{{ID: object.ID{n}, Version: object.FirstVersion, Digest: crypto.Hash{n}}},
		Calls:   []transaction.Call{transaction.Transfer(transaction.InputArg(0), transaction.AddressArg(addr(9)))},
		Expect:  []transaction.Expectation{transaction.ExpectsCoin(addr(9), amount.Unit)},
		MaxFee:  1000,
		Expiry:  100,
		Witness: []transaction.Witness{transaction.SignatureWitness(make([]byte, 32), make([]byte, 64))},
	}
}

func block(txs ...*transaction.Transaction) *Block {
	return &Block{
		Header: Header{
			Timestamp:       1700000000,
			AncestorHash:    crypto.Hash{0xAA},
			TransactionHash: Root(txs),
			StateHash:       crypto.Hash{0xEE},
			Proposer:        addr(1),
		},
		Transactions: txs,
	}
}

func TestValidateAccepts(t *testing.T) {
	if err := block(tx(1), tx(2)).Validate(); err != nil {
		t.Fatalf("block rejected: %v", err)
	}
	if err := block().Validate(); err != nil {
		t.Fatalf("empty block rejected: %v", err)
	}
}

func TestValidateRejects(t *testing.T) {
	cases := []struct {
		name string
		mut  func(*Block)
	}{
		{"carries no timestamp", func(b *Block) { b.Header.Timestamp = 0 }},
		{"carries no state hash", func(b *Block) { b.Header.StateHash = crypto.Hash{} }},
		{"names no proposer", func(b *Block) { b.Header.Proposer = crypto.Address{} }},
		{"carries no transaction root", func(b *Block) { b.Header.TransactionHash = crypto.Hash{} }},
		{"names a root the body does not build", func(b *Block) { b.Header.TransactionHash = crypto.Hash{0xAB} }},
		{"carries more transactions than the limit", func(b *Block) {
			for len(b.Transactions) <= MaxTransactions {
				b.Transactions = append(b.Transactions, b.Transactions[0])
			}
			b.Header.TransactionHash = Root(b.Transactions)
		}},
		{"holds a transaction that does not validate", func(b *Block) {
			b.Transactions[0].MaxFee = 0
			b.Header.TransactionHash = Root(b.Transactions)
		}},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			b := block(tx(1))
			c.mut(b)
			if err := b.Validate(); err == nil {
				t.Fatalf("block that %s was accepted", c.name)
			}
		})
	}
}

func TestEncodeRoundTrips(t *testing.T) {
	in := block(tx(1), tx(2), tx(3))

	var buf bytes.Buffer
	if err := in.Encode(&buf); err != nil {
		t.Fatalf("encode: %v", err)
	}

	var out Block
	if err := out.Decode(bytes.NewReader(buf.Bytes())); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if err := out.Validate(); err != nil {
		t.Fatalf("decoded block does not validate: %v", err)
	}
	if out.Hash() != in.Hash() {
		t.Fatal("round trip changed the block hash")
	}

	again, err := out.Bytes()
	if err != nil {
		t.Fatalf("re-encode: %v", err)
	}
	if !bytes.Equal(again, buf.Bytes()) {
		t.Fatal("re-encoding the decoded block gave different bytes")
	}
}

func TestHashCoversEveryHeaderField(t *testing.T) {
	base := block(tx(1))

	cases := []struct {
		name string
		mut  func(*Header)
	}{
		{"timestamp", func(h *Header) { h.Timestamp++ }},
		{"ancestor", func(h *Header) { h.AncestorHash = crypto.Hash{2} }},
		{"transaction root", func(h *Header) { h.TransactionHash = crypto.Hash{0xAB} }},
		{"state", func(h *Header) { h.StateHash = crypto.Hash{0xCD} }},
		{"proposer", func(h *Header) { h.Proposer = addr(7) }},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := base.Header
			c.mut(&h)
			if h.Hash() == base.Header.Hash() {
				t.Fatalf("changing %s left the hash unchanged", c.name)
			}
		})
	}
}

func TestHeaderWire(t *testing.T) {
	h := Header{
		Timestamp:       3,
		AncestorHash:    crypto.Hash{0x11},
		TransactionHash: crypto.Hash{0x22},
		StateHash:       crypto.Hash{0x33},
		Proposer:        addr(0x44),
	}

	zeros := func(n int) string { return strings.Repeat("00", n) }
	want := "0300000000000000" +
		"11" + zeros(31) + "22" + zeros(31) + "33" + zeros(31) + "44" + zeros(31)

	b, err := encoding.Encode2Bytes(&h)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if got := hex.EncodeToString(b); got != want {
		t.Fatalf("encoded %s\n    want %s", got, want)
	}
	if len(b) != 8+32*4 {
		t.Fatalf("header is %d bytes", len(b))
	}
}

func TestTransactionByHash(t *testing.T) {
	b := block(tx(1), tx(2))
	want := b.Transactions[1].ID()

	got := b.Transactions.TransactionByHash(want)
	if got == nil {
		t.Fatal("transaction that is in the block was not found")
	}
	if got.ID() != want {
		t.Fatal("found the wrong transaction")
	}
	if b.Transactions.TransactionByHash(crypto.Hash{0xFF}) != nil {
		t.Fatal("found a transaction that is not in the block")
	}
}

func TestRootDependsOnOrderContentAndWitness(t *testing.T) {
	a, c := tx(1), tx(2)
	if Root(Transactions{a, c}) == Root(Transactions{c, a}) {
		t.Fatal("the root ignores transaction order")
	}
	if Root(Transactions{a}) == Root(Transactions{c}) {
		t.Fatal("the root ignores transaction content")
	}
	if Root(nil) != Root(Transactions{}) {
		t.Fatal("a nil body and an empty one build different roots")
	}
	if Root(nil).Empty() {
		t.Fatal("an empty body builds the zero root, which Header.Validate refuses")
	}

	// Same ID, different signature: the root must still move, or a relayer
	// could swap witnesses inside a block without touching its header.
	signed := tx(1)
	signed.Witness = []transaction.Witness{transaction.SignatureWitness(make([]byte, 32), bytes.Repeat([]byte{1}, 64))}
	if signed.ID() != a.ID() {
		t.Fatal("fixture: changing the witness changed the ID")
	}
	if Root(Transactions{signed}) == Root(Transactions{a}) {
		t.Fatal("the root ignores witnesses")
	}
}
