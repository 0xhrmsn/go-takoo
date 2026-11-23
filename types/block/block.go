package block

import (
	"go-takoo/crypto"
	"go-takoo/crypto/merkle"
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

func (txs Transactions) Len() int {
	return len(txs)
}

func (txs *Transactions) TransactionByHash(d transaction.Domain, h crypto.Hash) *transaction.Transaction {
	for _, tx := range *txs {
		if tx.ID(d) == h {
			return tx
		}
	}

	return nil
}

func (txs *Transactions) Root() crypto.Hash {
	leaves := make([][]byte, txs.Len())
	for i, tx := range *txs {
		wire := tx.WireHash()
		leaves[i] = wire[:]
	}

	return crypto.Hash(merkle.NewMerkle(leaves).Root())
}

type Block struct {
	header       Header
	transactions Transactions
}

func (b *Block) Header() Header {
	return b.header
}

func (b *Block) Transactions() Transactions {
	return b.transactions
}
