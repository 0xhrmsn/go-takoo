package hd

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
	"testing"
)

func scalar(t *testing.T, k *DerivedKey) string {
	t.Helper()
	priv, err := k.PrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	return new(big.Int).SetBytes(priv.Bytes()).String()
}

// Official EIP-2333 vectors, all four: the master key from a seed, and one
// child of it.
func TestEIP2333Vectors(t *testing.T) {
	for _, v := range []struct {
		seed, master string
		index        uint32
		child        string
	}{
		{"c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04",
			"6083874454709270928345386274498605044986640685124978867557563392430687146096", 0,
			"20397789859736650942317412262472558107875392172444076792671091975210932703118"},
		{"3141592653589793238462643383279502884197169399375105820974944592",
			"29757020647961307431480504535336562678282505419141012933316116377660817309383", 3141592653,
			"25457201688850691947727629385191704516744796114925897962676248250929345014287"},
		{"0099FF991111002299DD7744EE3355BBDD8844115566CC55663355668888CC00",
			"27580842291869792442942448775674722299803720648445448686099262467207037398656", 4294967295,
			"29358610794459428860402234341874281240803786294062035874021252734817515685787"},
		{"d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3",
			"19022158461524446591288038168518313374041767046816487870552872741050760015818", 42,
			"31372231650479070279774297061823572166496564838472787488249775572789064611981"},
	} {
		seed, _ := hex.DecodeString(v.seed)
		master, err := NewMasterKey(seed)
		if err != nil {
			t.Fatal(err)
		}
		if got := scalar(t, master); got != v.master {
			t.Errorf("master = %s, want %s", got, v.master)
		}
		child, err := master.Derive(v.index)
		if err != nil {
			t.Fatal(err)
		}
		if got := scalar(t, child); got != v.child {
			t.Errorf("child %d = %s, want %s", v.index, got, v.child)
		}
	}
	for _, n := range []int{0, minSeedSize - 1, maxSeedSize + 1} {
		if _, err := NewMasterKey(make([]byte, n)); err == nil {
			t.Errorf("accepted a %d-byte seed", n)
		}
	}
	for _, n := range []int{minSeedSize, maxSeedSize} {
		if _, err := NewMasterKey(make([]byte, n)); err != nil {
			t.Errorf("refused a %d-byte seed: %v", n, err)
		}
	}
}

func TestDerivePathMatchesStepByStep(t *testing.T) {
	master, err := NewMasterKey(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	path := DerivationPath{12381, 1, 0, 0, 0}
	direct, err := master.DerivePath(path)
	if err != nil {
		t.Fatal(err)
	}
	step := master
	for _, index := range path {
		if step, err = step.Derive(index); err != nil {
			t.Fatal(err)
		}
	}
	if scalar(t, direct) != scalar(t, step) || direct.Path().String() != path.String() {
		t.Fatal("DerivePath and Derive disagree")
	}

	// Siblings must not share a path: a parent whose path has spare capacity
	// would otherwise hand the same backing array to both.
	parent, err := master.DerivePath(DerivationPath{1, 2, 3})
	if err != nil {
		t.Fatal(err)
	}
	first, err := parent.Derive(0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parent.Derive(1); err != nil {
		t.Fatal(err)
	}
	if got := first.Path().String(); got != "m/1/2/3/0" {
		t.Fatalf("the first child's path became %s", got)
	}

	// An empty path gives a copy, as in ed25519/hd: wiping what it returns
	// must not wipe the key it came from.
	same, err := master.DerivePath(nil)
	if err != nil {
		t.Fatal(err)
	}
	if same == master || same.key == master.key || scalar(t, same) != scalar(t, master) {
		t.Fatal("DerivePath(nil) did not return an equal, independent key")
	}
}

func TestDerivationDepthIsBounded(t *testing.T) {
	master, err := NewMasterKey(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	deepest, err := master.DerivePath(make(DerivationPath, maxDepth))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := deepest.Derive(0); err == nil {
		t.Error("Derive went past the maximum depth")
	}
	if _, err := master.DerivePath(make(DerivationPath, maxDepth+1)); err == nil {
		t.Error("DerivePath went past the maximum depth")
	}
}

func TestDerivedKeyIsRedactedWhenPrinted(t *testing.T) {
	master, err := NewMasterKey(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	priv, err := master.PrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	for _, out := range []string{
		fmt.Sprint(master), fmt.Sprintf("%v", master), fmt.Sprintf("%s", master), fmt.Sprintf("%+v", master),
		fmt.Sprintf("%#v", *master), fmt.Sprintf("%x", master),
		fmt.Sprintf("%v", struct{ Key *DerivedKey }{master}),
	} {
		if strings.Contains(out, priv.String()) || strings.Contains(out, hex.EncodeToString(priv.Bytes())) {
			t.Errorf("printing leaked the key: %s", out)
		}
	}
}

func TestParseDerivationPath(t *testing.T) {
	for _, s := range []string{"m", "m/12381/1/0/0/0"} {
		p, err := ParseDerivationPath(s)
		if err != nil || p.String() != s {
			t.Errorf("%q parsed as %q, %v", s, p.String(), err)
		}
	}
	for _, s := range []string{"", "x/1", "m/", "m/1'", "m/01", "m/4294967296", "m/a"} {
		if _, err := ParseDerivationPath(s); err == nil {
			t.Errorf("%q accepted", s)
		}
	}
	for s, want := range map[string]string{
		"m/4294967296":                            "out of range",
		"m" + strings.Repeat("/0", maxDepth+1):    "exceeds",
		"m/" + strings.Repeat("1", maxPathLength): "at most",
	} {
		if _, err := ParseDerivationPath(s); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%.20q: err = %v, want %q", s, err, want)
		}
	}
}
