package block

import (
	"slices"

	"go-takoo/crypto"
	"go-takoo/types/transaction"
)

type Header struct {
	Version       uint8
	Epoch         uint64
	Round         uint64
	Timestamp     uint32
	AncestorHash  crypto.Hash
	AncestorProof interface{}
	MerkleHash    crypto.Hash
	StateHash     crypto.Hash
	Proposer      crypto.Address
}

type Transactions []*transaction.Transaction

type Block struct {
	header       Header
	transactions Transactions
}

func (b *Block) Header() Header {
	return b.header
}

func (b *Block) Transactions() Transactions {
	out := slices.Clone(b.transactions)
	for i, tx := range out {
		if tx == nil {
			continue
		}
		snapshot := *tx
		snapshot.Body.Calls = slices.Clone(tx.Body.Calls)
		snapshot.Auths = slices.Clone(tx.Auths)
		for j := range snapshot.Auths {
			snapshot.Auths[j].PK = slices.Clone(tx.Auths[j].PK)
			snapshot.Auths[j].Sign = slices.Clone(tx.Auths[j].Sign)
		}
		out[i] = &snapshot
	}
	return out
}
