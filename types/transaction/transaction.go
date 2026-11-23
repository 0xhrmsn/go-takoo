package transaction

type Body struct {
	ChainID  uint32
	Version  uint8
	Expiry   uint64
	GasPrice uint64
	Calls    []Call
}

type Transaction struct {
	Body  Body
	Auths []Auth
}

type Call struct {
	Method uint64
}

type Auth struct {
	PK   []byte
	Sign []byte
}

type ()
