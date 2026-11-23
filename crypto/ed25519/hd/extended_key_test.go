package hd

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"

	"go-takoo/crypto"
	"go-takoo/crypto/bech32m"
)

type vectorNode struct {
	path, chainCode, key, pub string
}

// The ed25519 vectors from SLIP-0010. Public keys drop the 0x00 prefix the
// spec writes them with.
var slip10Vectors = []struct {
	seed  string
	nodes []vectorNode
}{
	{
		seed: "000102030405060708090a0b0c0d0e0f",
		nodes: []vectorNode{
			{"m", "90046a93de5380a72b5e45010748567d5ea02bbf6522f979e05c0d8d8ca9fffb", "2b4be7f19ee27bbf30c667b642d5f4aa69fd169872f8fc3059c08ebae2eb19e7", "a4b2856bfec510abab89753fac1ac0e1112364e7d250545963f135f2a33188ed"},
			{"m/0'", "8b59aa11380b624e81507a27fedda59fea6d0b779a778918a2fd3590e16e9c69", "68e0fe46dfb67e368c75379acec591dad19df3cde26e63b93a8e704f1dade7a3", "8c8a13df77a28f3445213a0f432fde644acaa215fc72dcdf300d5efaa85d350c"},
			{"m/0'/1'", "a320425f77d1b5c2505a6b1b27382b37368ee640e3557c315416801243552f14", "b1d0bad404bf35da785a64ca1ac54b2617211d2777696fbffaf208f746ae84f2", "1932a5270f335bed617d5b935c80aedb1a35bd9fc1e31acafd5372c30f5c1187"},
			{"m/0'/1'/2'", "2e69929e00b5ab250f49c3fb1c12f252de4fed2c1db88387094a0f8c4c9ccd6c", "92a5b23c0b8a99e37d07df3fb9966917f5d06e02ddbd909c7e184371463e9fc9", "ae98736566d30ed0e9d2f4486a64bc95740d89c7db33f52121f8ea8f76ff0fc1"},
			{"m/0'/1'/2'/2'", "8f6d87f93d750e0efccda017d662a1b31a266e4a6f5993b15f5c1f07f74dd5cc", "30d1dc7e5fc04c31219ab25a27ae00b50f6fd66622f6e9c913253d6511d1e662", "8abae2d66361c879b900d204ad2cc4984fa2aa344dd7ddc46007329ac76c429c"},
			{"m/0'/1'/2'/2'/1000000000'", "68789923a0cac2cd5a29172a475fe9e0fb14cd6adb5ad98a3fa70333e7afa230", "8f94d394a8e8fd6b1bc2f3f49f5c47e385281d5c17e65324b0f62483e37e8793", "3c24da049451555d51a7014a37337aa4e12d41e485abccfa46b47dfb2af54b7a"},
		},
	},
	{
		seed: "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
		nodes: []vectorNode{
			{"m", "ef70a74db9c3a5af931b5fe73ed8e1a53464133654fd55e7a66f8570b8e33c3b", "171cb88b1b3c1db25add599712e36245d75bc65a1a5c9e18d76f9f2b1eab4012", "8fe9693f8fa62a4305a140b9764c5ee01e455963744fe18204b4fb948249308a"},
			{"m/0'", "0b78a3226f915c082bf118f83618a618ab6dec793752624cbeb622acb562862d", "1559eb2bbec5790b0c65d8693e4d0875b1747f4970ae8b650486ed7470845635", "86fab68dcb57aa196c77c5f264f215a112c22a912c10d123b0d03c3c28ef1037"},
			{"m/0'/2147483647'", "138f0b2551bcafeca6ff2aa88ba8ed0ed8de070841f0c4ef0165df8181eaad7f", "ea4f5bfe8694d8bb74b7b59404632fd5968b774ed545e810de9c32a4fb4192f4", "5ba3b9ac6e90e83effcd25ac4e58a1365a9e35a3d3ae5eb07b9e4d90bcf7506d"},
			{"m/0'/2147483647'/1'", "73bd9fff1cfbde33a1b846c27085f711c0fe2d66fd32e139d3ebc28e5a4a6b90", "3757c7577170179c7868353ada796c839135b3d30554bbb74a4b1e4a5a58505c", "2e66aa57069c86cc18249aecf5cb5a9cebbfd6fadeab056254763874a9352b45"},
			{"m/0'/2147483647'/1'/2147483646'", "0902fe8a29f9140480a00ef244bd183e8a13288e4412d8389d140aac1794825a", "5837736c89570de861ebc173b1086da4f505d4adb387c6a1b1342d5e4ac9ec72", "e33c0f7d81d843c572275f287498e8d408654fdf0d1e065b84e2e6f157aab09b"},
			{"m/0'/2147483647'/1'/2147483646'/2'", "5d70af781f3a37b829f0d060924d5e960bdc02e85423494afc0b1a41bbe196d4", "551d333177df541ad876a60ea71f00447931c0a9da16f227c11ea080d7391b8d", "47150c75db263559a70d5778bf36abbab30fb061ad69f69ece61a72b0cfa4fc0"},
		},
	},
}

func mustHex(tb testing.TB, s string) []byte {
	tb.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		tb.Fatal(err)
	}
	return b
}

func hardened(indexes ...uint32) DerivationPath {
	p := make(DerivationPath, len(indexes))
	for i, index := range indexes {
		p[i] = index + HardenedKeyStart
	}
	return p
}

func testMaster(tb testing.TB) ExtendedKey {
	tb.Helper()
	master, err := NewMasterKey(mustHex(tb, slip10Vectors[0].seed))
	if err != nil {
		tb.Fatal(err)
	}
	return master
}

// validPayload builds an extended key payload that passes every check, for
// the reject cases to break one field at a time.
func validPayload(depth int, index uint32) []byte {
	b := []byte{extendedKeyVersion, byte(crypto.SchemeEd25519), byte(depth)}
	for range depth {
		b = binary.BigEndian.AppendUint32(b, index)
	}
	b = append(b, bytes.Repeat([]byte{0x11}, nodeChainCodeSize)...)
	return append(b, bytes.Repeat([]byte{0x22}, nodeKeySize)...)
}

func encodeXprv(tb testing.TB, hrp string, payload []byte) string {
	tb.Helper()
	s, err := bech32m.EncodeFromBase256NoLimit(hrp, payload)
	if err != nil {
		tb.Fatal(err)
	}
	return s
}

func TestDerivationMatchesSLIP10Vectors(t *testing.T) {
	for _, v := range slip10Vectors {
		master, err := NewMasterKey(mustHex(t, v.seed))
		if err != nil {
			t.Fatal(err)
		}
		for _, n := range v.nodes {
			t.Run(n.path, func(t *testing.T) {
				path, err := ParseDerivationPath(n.path)
				if err != nil {
					t.Fatal(err)
				}
				node, err := master.DerivePath(path)
				if err != nil {
					t.Fatal(err)
				}
				priv, err := node.PrivateKey()
				if err != nil {
					t.Fatal(err)
				}
				if got := hex.EncodeToString(node.chainCode[:]); got != n.chainCode {
					t.Errorf("chain code %s, want %s", got, n.chainCode)
				}
				if got := hex.EncodeToString(node.key[:]); got != n.key {
					t.Errorf("key %s, want %s", got, n.key)
				}
				if got := hex.EncodeToString(priv.Public().Bytes()); got != n.pub {
					t.Errorf("public key %s, want %s", got, n.pub)
				}
				if got := node.Path().String(); got != n.path {
					t.Errorf("path %s, want %s", got, n.path)
				}
			})
		}
	}
}

func TestNewMasterKeyChecksSeedSize(t *testing.T) {
	for _, n := range []int{0, minSeedSize - 1, maxSeedSize + 1} {
		if _, err := NewMasterKey(make([]byte, n)); err == nil || !strings.Contains(err.Error(), "seed must be 16 to 64 bytes") {
			t.Errorf("%d-byte seed: err = %v", n, err)
		}
	}
	for _, n := range []int{minSeedSize, maxSeedSize} {
		if _, err := NewMasterKey(make([]byte, n)); err != nil {
			t.Errorf("%d-byte seed: %v", n, err)
		}
	}
}

func TestNewMasterKeyLeavesTheSeedAlone(t *testing.T) {
	seed := mustHex(t, slip10Vectors[0].seed)
	want := bytes.Clone(seed)
	_, _ = NewMasterKey(seed)
	if !bytes.Equal(seed, want) {
		t.Fatalf("seed changed to %x", seed)
	}
}

// Under fips140=only, crypto/hmac refuses the 12-byte "ed25519 seed" key, so
// the mode can only be set before the process starts: the test runs itself
// again with it.
func TestNewMasterKeyRefusesFIPSOnlyMode(t *testing.T) {
	if os.Getenv("HD_FIPS_ONLY_CHILD") == "1" {
		_, err := NewMasterKey(make([]byte, 32))
		if err == nil || !strings.Contains(err.Error(), "fips140=only") {
			t.Fatalf("err = %v", err)
		}
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestNewMasterKeyRefusesFIPSOnlyMode$", "-test.v")
	cmd.Env = append(os.Environ(), "HD_FIPS_ONLY_CHILD=1", "GODEBUG=fips140=only")
	out, err := cmd.CombinedOutput()
	if err != nil || !bytes.Contains(out, []byte("--- PASS: TestNewMasterKeyRefusesFIPSOnlyMode")) {
		t.Fatalf("child: %v\n%s", err, out)
	}
}

func TestDeriveRejects(t *testing.T) {
	master := testMaster(t)
	deepest, err := master.DerivePath(hardened(make([]uint32, maxDepth)...))
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name  string
		key   *ExtendedKey
		index uint32
		want  string
	}{
		{"non-hardened", &master, 5, "ed25519 supports only hardened derivation: child index 5"},
		{"past max depth", deepest, HardenedKeyStart, "derivation is deeper than 16 levels: 17 levels"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			child, err := tt.key.Derive(tt.index)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("child %v, err = %v, want %q", child, err, tt.want)
			}
		})
	}
}

func TestDerivePathMatchesDeriveStepByStep(t *testing.T) {
	master := testMaster(t)
	path := hardened(44, 784, 0, 0, 7)
	want := &master
	for _, index := range path {
		var err error
		if want, err = want.Derive(index); err != nil {
			t.Fatal(err)
		}
	}
	got, err := master.DerivePath(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.String() != want.String() {
		t.Fatalf("DerivePath %s, Derive chain %s", got, want)
	}
}

func TestDerivePathLeavesTheReceiverAlone(t *testing.T) {
	master := testMaster(t)
	before := master.String()
	if _, err := master.DerivePath(hardened(0, 1, 2)); err != nil {
		t.Fatal(err)
	}
	if master.String() != before {
		t.Fatal("DerivePath changed its receiver")
	}
	// An empty path gives a node equal to the receiver but not the receiver:
	// wiping it must leave the master intact.
	same, err := master.DerivePath(nil)
	if err != nil || same == &master || same.String() != before {
		t.Fatalf("empty path: same pointer %v, equal %v, err %v", same == &master, same != nil && same.String() == before, err)
	}
	clear(same.key[:])
	clear(same.chainCode[:])
	if master.String() != before {
		t.Fatal("wiping the node from an empty path wiped the master")
	}
}

func TestDerivePathRejects(t *testing.T) {
	master := testMaster(t)
	account, _ := master.DerivePath(hardened(make([]uint32, maxDepth-1)...))
	tests := []struct {
		name string
		key  *ExtendedKey
		path DerivationPath
		want string
	}{
		{"past max depth from master", &master, hardened(make([]uint32, maxDepth+1)...), "deeper than 16 levels: 17 levels"},
		{"past max depth from a child", account, hardened(0, 0), "deeper than 16 levels: 17 levels"},
		{"non-hardened after hardened", &master, DerivationPath{HardenedKeyStart, 5}, "child index 5"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			node, err := tt.key.DerivePath(tt.path)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("node %v, err = %v, want %q", node, err, tt.want)
			}
		})
	}
}

func TestPathIsACopy(t *testing.T) {
	master := testMaster(t)
	if master.Path() != nil {
		t.Fatalf("master path %v, want nil", master.Path())
	}
	node, _ := master.DerivePath(hardened(44, 784, 0))
	before := node.String()
	node.Path()[2] = 5
	if node.String() != before {
		t.Fatal("writing into Path changed the key")
	}
}

func TestPrivateKeyLeavesTheExtendedKeyIntact(t *testing.T) {
	master := testMaster(t)
	node, _ := master.DerivePath(hardened(0))
	before := node.String()
	child, _ := node.Derive(HardenedKeyStart)
	for range 2 {
		if _, err := node.PrivateKey(); err != nil {
			t.Fatal(err)
		}
	}
	if node.String() != before {
		t.Fatal("PrivateKey changed the extended key")
	}
	if again, _ := node.Derive(HardenedKeyStart); again.String() != child.String() {
		t.Fatal("PrivateKey changed the children")
	}
}

func TestStringLayout(t *testing.T) {
	master := testMaster(t)
	tests := []struct {
		path  DerivationPath
		chars int
	}{
		{nil, 119},
		{hardened(44, 784, 0), 138},
		{hardened(44, 784, 0, 0, 0), 151},
		{hardened(make([]uint32, maxDepth)...), maxExtendedKeyLength},
	}
	if maxExtendedKeyLength != 221 {
		t.Fatalf("maxExtendedKeyLength %d, want 221", maxExtendedKeyLength)
	}
	for _, tt := range tests {
		t.Run(tt.path.String(), func(t *testing.T) {
			node, err := master.DerivePath(tt.path)
			if err != nil {
				t.Fatal(err)
			}
			s := node.String()
			if len(s) != tt.chars {
				t.Errorf("%d chars, want %d", len(s), tt.chars)
			}
			hrp, b, err := bech32m.DecodeToBase256NoLimit(s)
			if err != nil || hrp != crypto.ExtendedPrivateKeyHRP {
				t.Fatalf("decode: %q %v", hrp, err)
			}
			depth := len(tt.path)
			want := []byte{extendedKeyVersion, byte(crypto.SchemeEd25519), byte(depth)}
			for _, index := range tt.path {
				want = binary.BigEndian.AppendUint32(want, index)
			}
			want = append(want, node.chainCode[:]...)
			want = append(want, node.key[:]...)
			if !bytes.Equal(b, want) {
				t.Fatalf("payload\n got  %x\n want %x", b, want)
			}
		})
	}
}

func TestExtendedKeyStringRoundTrip(t *testing.T) {
	for _, v := range slip10Vectors {
		master, err := NewMasterKey(mustHex(t, v.seed))
		if err != nil {
			t.Fatal(err)
		}
		for _, n := range v.nodes {
			path, err := ParseDerivationPath(n.path)
			if err != nil {
				t.Fatal(err)
			}
			node, err := master.DerivePath(path)
			if err != nil {
				t.Fatal(err)
			}
			s := node.String()
			for _, in := range []string{s, strings.ToUpper(s)} {
				got, err := ExtendedKeyFromString(in)
				if err != nil {
					t.Fatalf("%s: %v", n.path, err)
				}
				if got.String() != s || got.key != node.key || got.chainCode != node.chainCode || !slices.Equal(got.path, node.path) {
					t.Fatalf("%s: %q did not come back as %q", n.path, in, s)
				}
			}
		}
	}
}

// A leaked xprv gives away every key derived below it. String is the
// deliberate export; every other way of printing it is redacted.
func TestExtendedKeyIsRedactedWhenPrinted(t *testing.T) {
	master := testMaster(t)
	child, err := master.DerivePath(hardened(44, 0))
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range []*ExtendedKey{&master, child} {
		secrets := []string{k.String(), hex.EncodeToString(k.key[:]), hex.EncodeToString(k.chainCode[:])}
		for _, out := range []string{
			fmt.Sprint(k), fmt.Sprintf("%v", k), fmt.Sprintf("%s", k), fmt.Sprintf("%+v", k),
			fmt.Sprintf("%#v", k), fmt.Sprintf("%x", k), fmt.Sprintf("%v", *k),
			fmt.Sprintf("%v", struct{ Key *ExtendedKey }{k}), fmt.Sprintf("%+v", struct{ Key ExtendedKey }{*k}),
		} {
			for _, secret := range secrets {
				if strings.Contains(out, secret) {
					t.Errorf("printing leaked the key: %s", out)
				}
			}
		}
	}
}

func TestExtendedKeyFromStringRejects(t *testing.T) {
	valid := encodeXprv(t, crypto.ExtendedPrivateKeyHRP, validPayload(1, HardenedKeyStart))
	if _, err := ExtendedKeyFromString(valid); err != nil {
		t.Fatalf("valid payload: %v", err)
	}
	mutated := func(f func(b []byte)) string {
		b := validPayload(1, HardenedKeyStart)
		f(b)
		return encodeXprv(t, crypto.ExtendedPrivateKeyHRP, b)
	}
	master := testMaster(t)
	oldLayout := append(append([]byte{0}, master.chainCode[:]...), master.key[:]...)
	badChecksum := valid[:len(valid)-1] + "q"
	if badChecksum == valid {
		badChecksum = valid[:len(valid)-1] + "p"
	}

	tests := []struct {
		name, in, want string
	}{
		{"empty", "", "empty extended key string"},
		{"too long", strings.Repeat("q", maxExtendedKeyLength+1), "222 bytes, want at most 221"},
		{"bad checksum", badChecksum, "invalid checksum"},
		{"wrong prefix", encodeXprv(t, crypto.PrivateKeyHRP, validPayload(1, HardenedKeyStart)), `prefix "prv", want "xprv"`},
		{"empty payload", encodeXprv(t, crypto.ExtendedPrivateKeyHRP, nil), "payload is 0 bytes, want at least 3"},
		{"short header", encodeXprv(t, crypto.ExtendedPrivateKeyHRP, []byte{0, 1}), "payload is 2 bytes, want at least 3"},
		{"version", mutated(func(b []byte) { b[0] = 1 }), "version 1, want 0"},
		{"scheme", mutated(func(b []byte) { b[1] = 2 }), "scheme 2, want 1"},
		{"layout without header", encodeXprv(t, crypto.ExtendedPrivateKeyHRP, oldLayout), "scheme 144, want 1"},
		{"depth past max", encodeXprv(t, crypto.ExtendedPrivateKeyHRP, append([]byte{0, 1, 17}, bytes.Repeat([]byte{0x80}, 128)...)), "depth 17, want at most 16"},
		{"depth and length disagree", mutated(func(b []byte) { b[2] = 2 }), "payload is 71 bytes, want 75 for depth 2"},
		{"non-hardened index", encodeXprv(t, crypto.ExtendedPrivateKeyHRP, validPayload(1, 5)), "child index 5 is not hardened"},
		{"zero chain code", mutated(func(b []byte) { clear(b[7:39]) }), "all-zero material"},
		{"zero key", mutated(func(b []byte) { clear(b[39:]) }), "all-zero material"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k, err := ExtendedKeyFromString(tt.in)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("key %v, err = %v, want %q", k, err, tt.want)
			}
		})
	}
}

func TestParseDerivationPath(t *testing.T) {
	tests := []struct {
		in   string
		want DerivationPath
	}{
		{"m", nil},
		{"m/44'/784'/0'", hardened(44, 784, 0)},
		{"m/0h/1H/2'", hardened(0, 1, 2)},
		{"m/2147483647'", hardened(2147483647)},
		{"m" + strings.Repeat("/0'", maxDepth), hardened(make([]uint32, maxDepth)...)},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, err := ParseDerivationPath(tt.in)
			if err != nil || !slices.Equal(got, tt.want) {
				t.Fatalf("got %v, %v, want %v", got, err, tt.want)
			}
		})
	}
}

func TestParseDerivationPathRejects(t *testing.T) {
	const invalid = "crypto/ed25519/hd: invalid derivation path: "
	tests := []struct {
		in, want string
	}{
		{"", invalid + "empty path"},
		{"m" + strings.Repeat("/0'", 65), invalid + "196 bytes, want at most 193"},
		{"M", invalid + `must start with "m"`},
		{"44'", invalid + `must start with "m"`},
		{"m44'", invalid + `must start with "m"`},
		{"x/0'", invalid + `must start with "m"`},
		{"m" + strings.Repeat("/0'", maxDepth+1), "crypto/ed25519/hd: derivation is deeper than 16 levels: 17 levels"},
		{"m/", invalid + "empty element"},
		{"m/0'//1'", invalid + "empty element"},
		{"m/0", `crypto/ed25519/hd: ed25519 supports only hardened derivation: element "0"`},
		{"m/01'", invalid + `element "01'" has a leading zero`},
		{"m/a'", invalid + `element "a'" is not a number`},
		{"m/'", invalid + `element "'" is not a number`},
		{"m/-1'", invalid + `element "-1'" is not a number`},
		{"m/0'x", invalid + `element "0'x" is not a number`},
		{"m/00", invalid + `element "00" has a leading zero`},
		{"m/2147483648'", invalid + `element "2147483648'" is out of range, want below 2147483648'`},
		{"m/99999999999'", invalid + `element "99999999999'" is out of range, want below 2147483648'`},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			p, err := ParseDerivationPath(tt.in)
			if err == nil || err.Error() != tt.want {
				t.Fatalf("path %v\n got  %v\n want %s", p, err, tt.want)
			}
		})
	}
}

func TestDerivationPathString(t *testing.T) {
	tests := []struct {
		path DerivationPath
		want string
	}{
		{nil, "m"},
		{hardened(44, 784, 0), "m/44'/784'/0'"},
		{DerivationPath{5, HardenedKeyStart + 5}, "m/5/5'"},
	}
	for _, tt := range tests {
		if got := tt.path.String(); got != tt.want {
			t.Errorf("%v: %q, want %q", []uint32(tt.path), got, tt.want)
		}
	}
}

func FuzzExtendedKeyFromString(f *testing.F) {
	master, _ := NewMasterKey(make([]byte, minSeedSize))
	for _, p := range []DerivationPath{nil, hardened(44), hardened(44, 784, 0, 0, 0), hardened(make([]uint32, maxDepth)...)} {
		node, _ := master.DerivePath(p)
		f.Add(node.String())
		f.Add(strings.ToUpper(node.String()))
	}
	f.Fuzz(func(t *testing.T, s string) {
		k, err := ExtendedKeyFromString(s)
		if err != nil {
			return
		}
		if out := k.String(); out != strings.ToLower(s) {
			t.Fatalf("%q accepted as a second spelling of %q", s, out)
		}
		if _, err := k.PrivateKey(); err != nil {
			t.Fatalf("accepted key cannot sign: %v", err)
		}
	})
}

// The string fuzzer rarely gets past the checksum. This one checksums whatever
// payload it makes up, so every check after decoding is exercised against a
// plain reading of the layout.
func FuzzExtendedKeyPayload(f *testing.F) {
	f.Add(validPayload(0, 0))
	f.Add(validPayload(3, HardenedKeyStart))
	f.Add(validPayload(maxDepth, HardenedKeyStart+7))
	f.Fuzz(func(t *testing.T, b []byte) {
		s, err := bech32m.EncodeFromBase256NoLimit(crypto.ExtendedPrivateKeyHRP, b)
		if err != nil {
			return
		}
		k, err := ExtendedKeyFromString(s)

		valid := len(b) >= 3 && b[0] == 0 && b[1] == 1 && int(b[2]) <= maxDepth && len(b) == 67+4*int(b[2])
		if valid {
			depth := int(b[2])
			for i := range depth {
				valid = valid && b[3+4*i]&0x80 != 0
			}
			valid = valid && slices.Max(b[3+4*depth:35+4*depth]) != 0 && slices.Max(b[35+4*depth:]) != 0
		}
		if valid != (err == nil) {
			t.Fatalf("payload %x: accepted %v, want %v: %v", b, err == nil, valid, err)
		}
		if err == nil && k.String() != s {
			t.Fatalf("payload %x: String does not give the input back", b)
		}
	})
}

func FuzzParseDerivationPath(f *testing.F) {
	for _, s := range []string{"m", "m/0'", "m/44'/784'/0'/0'/0'", "m/0h/1H", "m/2147483647'", "m/01'", "m/0", "M/0'", "m//"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		p, err := ParseDerivationPath(s)
		if err != nil {
			return
		}
		if len(p) > maxDepth {
			t.Fatalf("%q: %d levels", s, len(p))
		}
		for _, index := range p {
			if index < HardenedKeyStart {
				t.Fatalf("%q: non-hardened index %d", s, index)
			}
		}
		// Only the hardened marker may vary; any other difference is a second
		// spelling of the same path.
		normalized := strings.NewReplacer("h/", "'/", "H/", "'/").Replace(s + "/")
		if normalized[:len(normalized)-1] != p.String() {
			t.Fatalf("%q accepted as a second spelling of %q", s, p.String())
		}
	})
}

// sink keeps a discarded result reachable, so the compiler cannot drop the
// work being measured.
var sink byte

func BenchmarkNewMasterKey(b *testing.B) {
	seed := make([]byte, maxSeedSize)
	for b.Loop() {
		k, _ := NewMasterKey(seed)
		sink ^= k.key[0]
	}
}

func BenchmarkDerive(b *testing.B) {
	master := testMaster(b)
	for b.Loop() {
		k, _ := master.Derive(HardenedKeyStart)
		sink ^= k.key[0]
	}
}

func BenchmarkDerivePath(b *testing.B) {
	master := testMaster(b)
	path := hardened(44, 784, 0, 0, 0)
	for b.Loop() {
		k, _ := master.DerivePath(path)
		sink ^= k.key[0]
	}
}

func BenchmarkString(b *testing.B) {
	master := testMaster(b)
	node, _ := master.DerivePath(hardened(44, 784, 0, 0, 0))
	for b.Loop() {
		sink ^= node.String()[0]
	}
}

func BenchmarkExtendedKeyFromString(b *testing.B) {
	master := testMaster(b)
	node, _ := master.DerivePath(hardened(44, 784, 0, 0, 0))
	s := node.String()
	for b.Loop() {
		k, _ := ExtendedKeyFromString(s)
		sink ^= k.key[0]
	}
}

func BenchmarkParseDerivationPath(b *testing.B) {
	for b.Loop() {
		p, _ := ParseDerivationPath("m/44'/784'/0'/0'/0'")
		sink ^= byte(p[0])
	}
}

// With slices, a value copy shared its arrays with the original: clearing the
// copy wiped the original. A copy and a child must both stand on their own.
func TestCopiesAreIndependent(t *testing.T) {
	master := testMaster(t)
	before := master.String()

	cp := master
	clear(cp.key[:])
	clear(cp.chainCode[:])
	if master.String() != before {
		t.Fatal("clearing a value copy wiped the original")
	}

	child, err := master.Derive(HardenedKeyStart)
	if err != nil {
		t.Fatal(err)
	}
	again, _ := master.Derive(HardenedKeyStart)
	clear(child.key[:])
	clear(child.chainCode[:])
	if master.String() != before || again.key == child.key {
		t.Fatal("clearing a child reached its parent or its sibling")
	}
}

// Deriving from one master in many goroutines at once: Derive and DerivePath
// only read their receiver, so every result must match the serial one.
func TestConcurrentDerivationAgrees(t *testing.T) {
	master := testMaster(t)
	path := hardened(44, 784, 0, 0, 0)
	want, err := master.DerivePath(path)
	if err != nil {
		t.Fatal(err)
	}
	wantString := want.String()
	results := make(chan string, 64)
	for range 64 {
		go func() {
			node, err := master.DerivePath(path)
			if err != nil {
				results <- "error: " + err.Error()
				return
			}
			results <- node.String()
		}()
	}
	for range 64 {
		if got := <-results; got != wantString {
			t.Fatalf("a concurrent derivation gave %q", got)
		}
	}
	fresh := testMaster(t)
	if master.String() != fresh.String() {
		t.Fatal("concurrent derivation changed the master")
	}
}
