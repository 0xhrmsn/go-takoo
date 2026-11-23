package block

import (
	"testing"

	"go-takoo/types/transaction"
)

func TestBlockTransactionsAreDetached(t *testing.T) {
	tx := &transaction.Transaction{
		Body:  transaction.Body{Calls: []transaction.Call{{Method: 7}}},
		Auths: []transaction.Auth{{PK: []byte{1}, Sign: []byte{2}}},
	}
	b := Block{transactions: Transactions{tx, nil}}
	copy := b.Transactions()
	copy[0].Body.ChainID = 3
	copy[0].Body.Calls[0].Method = 4
	copy[0].Auths[0].PK[0] = 5
	copy[0].Auths[0].Sign[0] = 6
	copy[0].Auths[0] = transaction.Auth{}
	copy[0] = nil
	got := b.Transactions()
	if got[0].Body.ChainID != 0 || got[0].Body.Calls[0].Method != 7 ||
		got[0].Auths[0].PK[0] != 1 || got[0].Auths[0].Sign[0] != 2 || got[1] != nil {
		t.Fatal("mutating the snapshot changed the block")
	}
}
