package block

import (
	"go-takoo/crypto"
	"go-takoo/crypto/merkle"
	"go-takoo/types/transaction"
)

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
