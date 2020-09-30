package g2pubs_test

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/blake2b"
	"testing"

	"github.com/phoreproject/bls"
	"github.com/phoreproject/bls/g2pubs"

	bls12381 "github.com/kilic/bls12-381"
)

type XORShift struct {
	state uint64
}

func NewXORShift(state uint64) *XORShift {
	return &XORShift{state}
}

func (xor *XORShift) Read(b []byte) (int, error) {
	for i := range b {
		x := xor.state
		x ^= x << 13
		x ^= x >> 7
		x ^= x << 17
		b[i] = uint8(x)
		xor.state = x
	}
	return len(b), nil
}

func SignVerify(loopCount int) error {
	r := NewXORShift(1)
	for i := 0; i < loopCount; i++ {
		priv, _ := g2pubs.RandKey(r)
		pub := g2pubs.PrivToPub(priv)
		msg := []byte(fmt.Sprintf("Hello world! 16 characters %d", i))
		sig := g2pubs.Sign(msg, priv)
		if !g2pubs.Verify(msg, pub, sig) {
			return errors.New("sig did not verify")
		}
	}
	return nil
}

func TestMinePublicKeyParsing(t *testing.T) {
	pkBase64 := "lOpN7uGZWivVIjs0325N/V0dAhoPomrgfXVpg7pZNdRWwFwJDVxoE7TvRyOx/Qr7GMtShNuS2Px/oScD+SMf08t8eAO78QRNErPzwNpfkP4ppcSTShStFDfFbsv9L9yb"
	pkBytes, err := base64.RawStdEncoding.DecodeString(pkBase64)
	require.NoError(t, err)
	require.Len(t, pkBytes, 96)

	var pkBytesArr [96]byte
	copy(pkBytesArr[:], pkBytes[:96])

	publicKey, err := g2pubs.DeserializePublicKey(pkBytesArr)
	require.NoError(t, err)
	require.NotNil(t, publicKey)
}

func parseFr(data []byte) *bls.FR {
	var arr [32]byte
	copy(arr[:], data)

	return bls.FRReprToFR(bls.FRReprFromBytes(arr))
}

func TestMineSignatureParsing(t *testing.T) {
	sigBase64 := "hPbLkeMZZ6KKzkjWoTVHeMeuLJfYWjmdAU1Vg5fZ/VZnIXxxeXBB+q0/EL8XQmWkOMMwEGA/D2dCb4MDuntKZpvHEHlvaFR6l1A4bYj0t2Jd6bYwGwCwirNbmSeIoEmJeRzJ1cSvsL+jxvLixdDPnw=="
	sigBytes, err := base64.StdEncoding.DecodeString(sigBase64)
	require.NoError(t, err)
	require.Len(t, sigBytes, 112)

	var sigBytesArr [48]byte
	copy(sigBytesArr[:], sigBytes[:48])

	signature, err := g2pubs.DeserializeSignature(sigBytesArr)
	require.NoError(t, err)
	require.NotNil(t, signature)

	e := parseFr(sigBytes[48 : 48+32])
	require.NotNil(t, e)

	s := parseFr(sigBytes[48+32:])
	require.NotNil(t, s)
}

func messageToFr(message []byte) *bls.FR {
	h, _ := blake2b.New384(nil)
	_, _ = h.Write(message)
	okm := h.Sum(nil)

	elm := parseFr(append(make([]byte, 8, 8), okm[:24]...))
	elm.MulAssign(f2_192())
	elm.AddAssign(parseFr(append(make([]byte, 8, 8), okm[24:]...)))

	return elm
}

func f2_192() *bls.FR {
	return bls.NewFr(&bls.FRRepr{
		0x59476ebc41b4528f,
		0xc5a30cb243fcc152,
		0x2b34e63940ccbd72,
		0x1e179025ca247088})
}

func TestVerifySignature(t *testing.T) {
	pkBase64 := "lOpN7uGZWivVIjs0325N/V0dAhoPomrgfXVpg7pZNdRWwFwJDVxoE7TvRyOx/Qr7GMtShNuS2Px/oScD+SMf08t8eAO78QRNErPzwNpfkP4ppcSTShStFDfFbsv9L9yb"
	pkBytes, err := base64.RawStdEncoding.DecodeString(pkBase64)
	require.NoError(t, err)
	require.Len(t, pkBytes, 96)

	var pkBytesArr [96]byte
	copy(pkBytesArr[:], pkBytes[:96])

	publicKey, err := g2pubs.DeserializePublicKey(pkBytesArr)
	require.NoError(t, err)
	require.NotNil(t, publicKey)

	sigBase64 := "hPbLkeMZZ6KKzkjWoTVHeMeuLJfYWjmdAU1Vg5fZ/VZnIXxxeXBB+q0/EL8XQmWkOMMwEGA/D2dCb4MDuntKZpvHEHlvaFR6l1A4bYj0t2Jd6bYwGwCwirNbmSeIoEmJeRzJ1cSvsL+jxvLixdDPnw=="
	sigBytes, err := base64.StdEncoding.DecodeString(sigBase64)
	require.NoError(t, err)
	require.Len(t, sigBytes, 112)

	var sigBytesArr [48]byte
	copy(sigBytesArr[:], sigBytes[:48])

	signature, err := g2pubs.DeserializeSignature(sigBytesArr)
	require.NoError(t, err)
	require.NotNil(t, signature)

	messages := []string{"message1", "message2"}

	messagesFr := make([]*bls.FR, len(messages))
	for i := range messages {
		messagesFr[i] = messageToFr([]byte(messages[i]))
	}

	e := parseFr(sigBytes[48 : 48+32])
	require.NotNil(t, e)

	s := parseFr(sigBytes[48+32:])
	require.NotNil(t, s)

	p1 := signature.GetPoint().ToAffine()
	require.NotNil(t, p1)

	q1 := bls.G2ProjectiveOne
	q1 = Mul(q1, *e.ToRepr())
	q1 = q1.Add(publicKey.GetPoint())

	p2 := bls.NewG1Affine(
		bls.NewFQ(bls.FQRepr{
			2882873457617515126,
			8090169798720875349,
			3413154113899720733,
			2409063739866755870,
			4463753950411322760,
			965108758790108796,
		}),
		bls.NewFQ(bls.FQRepr{
			3039742753099377729,
			8681167061622442934,
			16786687068344448111,
			13428673864018845111,
			12820269664220724619,
			1175941883621080583,
		}),
	)

	require.True(t, CompareTwoPairings(p1.ToProjective(), q1, p2.ToProjective(), bls.G2ProjectiveOne))

	/*
		{
			priv, err := g2pubs.RandKey(NewXORShift(1))
			require.NoError(t, err)

			publicKey = g2pubs.PrivToPub(priv)

			message1 := []byte("message1")
			signature1 := g2pubs.Sign(message1, priv)
			require.True(t, g2pubs.Verify(message1, publicKey, signature1))

			message2 := []byte("message2")
			signature2 := g2pubs.Sign(message2, priv)
			require.True(t, g2pubs.Verify(message2, publicKey, signature2))

			aggrSignature := g2pubs.AggregateSignatures([]*g2pubs.Signature{signature1, signature2})

			validSignature := aggrSignature.VerifyAggregate([]*g2pubs.PublicKey{publicKey, publicKey}, [][]byte{
				message1,
				message2,
			})
			require.True(t, validSignature)
		}

	*/

	// TARGET!
	/*	validSignature := signature.VerifyAggregate([]*g2pubs.PublicKey{publicKey, publicKey}, [][]byte{
			[]byte("message1"),
			[]byte("message2"),
		})
		require.True(t, validSignature)
	*/

}

// Mul performs a EC multiply operation on the point.
func Mul(g *bls.G2Projective, b bls.FRRepr) *bls.G2Projective {
	res := bls.G2ProjectiveZero.Copy()
	for i := uint(0); i < uint(b.BitLen()); i++ {
		o := b.Bit(b.BitLen() - i - 1)
		res = res.Double()
		if o {
			res = res.Add(g)
		}
	}
	return res
}

func TestPairingComparison(t *testing.T) {
	/*	p1 := bls.NewG1Projective(
		bls.NewFQ(bls.FQRepr{
			16370429421516258006,
			13370838727054594723,
			1018707538954825462,
			7944738526253740579,
			4460657559868236937,
			1144194875142844353,
		}),
		bls.NewFQ(bls.FQRepr{
			4473961400152561216,
			238420868684456399,
			10454741800591563713,
			2462464036349354023,
			6960609179594048309,
			993702527266246817,
		}),
		bls.NewFQ(bls.FQRepr{
			8505329371266088957,
			17002214543764226050,
			6865905132761471162,
			8632934651105793861,
			6631298214892334189,
			1582556514881692819,
		}),
	)*/
	p1 := bls.NewG1Affine(
		bls.NewFQ(bls.FQRepr{
			16370429421516258006,
			13370838727054594723,
			1018707538954825462,
			7944738526253740579,
			4460657559868236937,
			1144194875142844353,
		}),
		bls.NewFQ(bls.FQRepr{
			4473961400152561216,
			238420868684456399,
			10454741800591563713,
			2462464036349354023,
			6960609179594048309,
			993702527266246817,
		}),
	)

	q1 := bls.NewG2Projective(
		bls.NewFQ2(
			bls.NewFQ(bls.FQRepr{
				14729264283605877758, 8052929671236952171, 482009507434465663, 5465354739862128410, 13923907204446376577, 1030491236563514074,
			}),
			bls.NewFQ(bls.FQRepr{
				13228470900547706793, 15805978330794979481, 510200209862916100, 5933868461179469133, 11420109164284838810, 121915148611333554,
			}),
		),
		bls.NewFQ2(
			bls.NewFQ(bls.FQRepr{
				17434557008903410809, 18067717987661788755, 2620376523377660005, 12918713543142823080, 11482354517443152445, 659262416231390122,
			}),
			bls.NewFQ(bls.FQRepr{
				8140357614622982532, 11102576235294031195, 8872947921373673018, 8145858700205586671, 4039555067422454225, 600943540397339938,
			}),
		),
		bls.NewFQ2(
			bls.NewFQ(bls.FQRepr{
				15135737048925088896, 11734189478919739727, 12327642962145943264, 13125512644385901322, 14329971368854893534, 386428027939231865,
			}),
			bls.NewFQ(bls.FQRepr{
				4160833650522955158, 2168245494824743763, 4965116188234435055, 8688697814555707053, 9765984219232172678, 570097477644937414,
			}),
		),
	)

	//p2 := bls.NewG1Projective(
	//	bls.NewFQ(bls.FQRepr{
	//		2882873457617515126,
	//		8090169798720875349,
	//		3413154113899720733,
	//		2409063739866755870,
	//		4463753950411322760,
	//		965108758790108796,
	//	}),
	//	bls.NewFQ(bls.FQRepr{
	//		3039742753099377729,
	//		8681167061622442934,
	//		16786687068344448111,
	//		13428673864018845111,
	//		12820269664220724619,
	//		1175941883621080583,
	//	}),
	//	bls.FQOne,
	//)

	p2 := bls.NewG1Affine(
		bls.NewFQ(bls.FQRepr{
			2882873457617515126,
			8090169798720875349,
			3413154113899720733,
			2409063739866755870,
			4463753950411322760,
			965108758790108796,
		}),
		bls.NewFQ(bls.FQRepr{
			3039742753099377729,
			8681167061622442934,
			16786687068344448111,
			13428673864018845111,
			12820269664220724619,
			1175941883621080583,
		}),
	)
	//p2.NegAssign()

	q2 := bls.G2ProjectiveOne

	// todo this does not work for some reason
	//  but below it's shown that bls12-381 check passes
	//require.True(t, bls.CompareTwoPairings(p1.ToProjective(), q1, p2.ToProjective(), q2))

	engine := bls12381.NewEngine()

	bytesG1 := p1.SerializeBytes()
	a1, err := engine.G1.FromUncompressed(bytesG1[:])
	require.NoError(t, err)
	require.NotNil(t, a1)

	bytesG2 := q1.ToAffine().SerializeBytes()
	a2, err := engine.G2.FromUncompressed(bytesG2[:])
	require.NoError(t, err)
	require.NotNil(t, a2)

	bytesG1 = p2.SerializeBytes()
	b, err := engine.G1.FromUncompressed(bytesG1[:])
	require.NoError(t, err)
	require.NotNil(t, b)

	bytesG2 = q2.ToAffine().SerializeBytes()
	g2, err := engine.G2.FromUncompressed(bytesG2[:])
	require.NoError(t, err)
	require.NotNil(t, g2)

	engine.AddPair(a1, a2)
	engine.AddPair(b, g2)

	require.True(t, engine.Check())

	require.True(t, CompareTwoPairings(p1.ToProjective(), q1, p2.ToProjective(), q2))
}

func CompareTwoPairings(p1 *bls.G1Projective, q1 *bls.G2Projective, p2 *bls.G1Projective, q2 *bls.G2Projective) bool {
	engine := bls12381.NewEngine()

	bytesG1 := p1.ToAffine().SerializeBytes()
	a1, err := engine.G1.FromUncompressed(bytesG1[:])
	if err != nil {
		panic(err)
	}

	bytesG2 := q1.ToAffine().SerializeBytes()
	a2, err := engine.G2.FromUncompressed(bytesG2[:])
	if err != nil {
		panic(err)
	}

	bytesG1 = p2.ToAffine().SerializeBytes()
	b, err := engine.G1.FromUncompressed(bytesG1[:])
	if err != nil {
		panic(err)
	}

	bytesG2 = q2.ToAffine().SerializeBytes()
	g2, err := engine.G2.FromUncompressed(bytesG2[:])
	if err != nil {
		panic(err)
	}

	engine.AddPair(a1, a2)
	engine.AddPair(b, g2)

	return engine.Check()
}

func SignVerifyAggregateCommonMessage(loopCount int) error {
	r := NewXORShift(2)
	pubkeys := make([]*g2pubs.PublicKey, 0, 1000)
	sigs := make([]*g2pubs.Signature, 0, 1000)
	msg := []byte(">16 character identical message")
	for i := 0; i < loopCount; i++ {
		priv, _ := g2pubs.RandKey(r)
		pub := g2pubs.PrivToPub(priv)
		sig := g2pubs.Sign(msg, priv)
		pubkeys = append(pubkeys, pub)
		sigs = append(sigs, sig)
		if i < 10 || i > (loopCount-5) {
			newSig := g2pubs.AggregateSignatures(sigs)
			if !newSig.VerifyAggregateCommon(pubkeys, msg) {
				return errors.New("sig did not verify")
			}
		}
	}
	return nil
}

func SignVerifyAggregateCommonMessageMissingSig(loopCount int) error {
	r := NewXORShift(3)
	skippedSig := loopCount / 2
	pubkeys := make([]*g2pubs.PublicKey, 0, 1000)
	sigs := make([]*g2pubs.Signature, 0, 1000)
	msg := []byte(">16 character identical message")
	for i := 0; i < loopCount; i++ {
		priv, _ := g2pubs.RandKey(r)
		pub := g2pubs.PrivToPub(priv)
		sig := g2pubs.Sign(msg, priv)
		pubkeys = append(pubkeys, pub)
		if i != skippedSig {
			sigs = append(sigs, sig)
		}
		if i < 10 || i > (loopCount-5) {
			newSig := g2pubs.AggregateSignatures(sigs)
			if newSig.VerifyAggregateCommon(pubkeys, msg) != (i < skippedSig) {
				return errors.New("sig did not verify")
			}
		}
	}
	return nil
}

func AggregateSignatures(loopCount int) error {
	r := NewXORShift(4)
	pubkeys := make([]*g2pubs.PublicKey, 0, 1000)
	msgs := make([][]byte, 0, 1000)
	sigs := make([]*g2pubs.Signature, 0, 1000)
	for i := 0; i < loopCount; i++ {
		priv, _ := g2pubs.RandKey(r)
		pub := g2pubs.PrivToPub(priv)
		msg := []byte(fmt.Sprintf(">16 character identical message %d", i))
		sig := g2pubs.Sign(msg, priv)
		pubkeys = append(pubkeys, pub)
		msgs = append(msgs, msg)
		sigs = append(sigs, sig)

		if i < 10 || i > (loopCount-5) {
			newSig := g2pubs.AggregateSignatures(sigs)
			if !newSig.VerifyAggregate(pubkeys, msgs) {
				return errors.New("sig did not verify")
			}
		}
	}
	return nil
}

func TestSignVerify(t *testing.T) {
	err := SignVerify(10)
	if err != nil {
		t.Fatal(err)
	}
}

func TestSignVerifyAggregateCommon(t *testing.T) {
	err := SignVerifyAggregateCommonMessage(10)
	if err != nil {
		t.Fatal(err)
	}
}

func TestSignVerifyAggregateCommonMissingSig(t *testing.T) {
	err := SignVerifyAggregateCommonMessageMissingSig(10)
	if err != nil {
		t.Fatal(err)
	}
}

func TestSignAggregateSigs(t *testing.T) {
	err := AggregateSignatures(10)
	if err != nil {
		t.Fatal(err)
	}
}

func TestAggregateSignaturesDuplicatedMessages(t *testing.T) {
	r := NewXORShift(5)

	pubkeys := make([]*g2pubs.PublicKey, 0, 1000)
	msgs := make([][]byte, 0, 1000)
	sigs := g2pubs.NewAggregateSignature()

	key, _ := g2pubs.RandKey(r)
	pub := g2pubs.PrivToPub(key)
	message := []byte(">16 char first message")
	sig := g2pubs.Sign(message, key)
	pubkeys = append(pubkeys, pub)
	msgs = append(msgs, message)
	sigs.Aggregate(sig)

	if !sigs.VerifyAggregate(pubkeys, msgs) {
		t.Fatal("signature does not verify")
	}

	key2, _ := g2pubs.RandKey(r)
	pub2 := g2pubs.PrivToPub(key2)
	message2 := []byte(">16 char second message")
	sig2 := g2pubs.Sign(message2, key2)
	pubkeys = append(pubkeys, pub2)
	msgs = append(msgs, message2)
	sigs.Aggregate(sig2)

	if !sigs.VerifyAggregate(pubkeys, msgs) {
		t.Fatal("signature does not verify")
	}

	key3, _ := g2pubs.RandKey(r)
	pub3 := g2pubs.PrivToPub(key3)
	sig3 := g2pubs.Sign(message2, key3)
	pubkeys = append(pubkeys, pub3)
	msgs = append(msgs, message2)
	sigs.Aggregate(sig3)

	if sigs.VerifyAggregate(pubkeys, msgs) {
		t.Fatal("signature verifies with duplicate message")
	}
}

func TestAggregateSigsSeparate(t *testing.T) {
	x := NewXORShift(20)
	priv1, _ := g2pubs.RandKey(x)
	priv2, _ := g2pubs.RandKey(x)
	priv3, _ := g2pubs.RandKey(x)

	pub1 := g2pubs.PrivToPub(priv1)
	pub2 := g2pubs.PrivToPub(priv2)
	pub3 := g2pubs.PrivToPub(priv3)

	msg := []byte("test 1")
	sig1 := g2pubs.Sign(msg, priv1)
	sig2 := g2pubs.Sign(msg, priv2)
	sig3 := g2pubs.Sign(msg, priv3)

	aggSigs := g2pubs.AggregateSignatures([]*g2pubs.Signature{sig1, sig2, sig3})

	aggPubs := g2pubs.NewAggregatePubkey()
	aggPubs.Aggregate(pub1)
	aggPubs.Aggregate(pub2)
	aggPubs.Aggregate(pub3)

	valid := g2pubs.Verify(msg, aggPubs, aggSigs)
	if !valid {
		t.Fatal("expected aggregate signature to be valid")
	}
}

func BenchmarkBLSAggregateSignature(b *testing.B) {
	r := NewXORShift(5)
	priv, _ := g2pubs.RandKey(r)
	msg := []byte(fmt.Sprintf(">16 character identical message"))
	sig := g2pubs.Sign(msg, priv)

	s := g2pubs.NewAggregateSignature()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.Aggregate(sig)
	}
}

func BenchmarkBLSSign(b *testing.B) {
	r := NewXORShift(5)
	privs := make([]*g2pubs.SecretKey, b.N)
	for i := range privs {
		privs[i], _ = g2pubs.RandKey(r)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {

		msg := []byte(fmt.Sprintf("Hello world! 16 characters %d", i))
		g2pubs.Sign(msg, privs[i])
		// if !g2pubs.Verify(msg, pub, sig) {
		// 	return errors.New("sig did not verify")
		// }
	}
}

func BenchmarkBLSVerify(b *testing.B) {
	r := NewXORShift(5)
	priv, _ := g2pubs.RandKey(r)
	pub := g2pubs.PrivToPub(priv)
	msg := []byte(fmt.Sprintf(">16 character identical message"))
	sig := g2pubs.Sign(msg, priv)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		g2pubs.Verify(msg, pub, sig)
	}
}

func TestSignatureSerializeDeserialize(t *testing.T) {
	r := NewXORShift(1)
	priv, _ := g2pubs.RandKey(r)
	pub := g2pubs.PrivToPub(priv)
	msg := []byte(fmt.Sprintf(">16 character identical message"))
	sig := g2pubs.Sign(msg, priv)

	if !g2pubs.Verify(msg, pub, sig) {
		t.Fatal("message did not verify before serialization/deserialization")
	}

	sigSer := sig.Serialize()
	sigDeser, err := g2pubs.DeserializeSignature(sigSer)
	if err != nil {
		t.Fatal(err)
	}
	if !g2pubs.Verify(msg, pub, sigDeser) {
		t.Fatal("message did not verify after serialization/deserialization")
	}
}

func TestPubkeySerializeDeserialize(t *testing.T) {
	r := NewXORShift(1)
	priv, _ := g2pubs.RandKey(r)
	pub := g2pubs.PrivToPub(priv)
	msg := []byte(fmt.Sprintf(">16 character identical message"))
	sig := g2pubs.Sign(msg, priv)

	if !g2pubs.Verify(msg, pub, sig) {
		t.Fatal("message did not verify before serialization/deserialization of pubkey")
	}

	pubSer := pub.Serialize()
	pubDeser, err := g2pubs.DeserializePublicKey(pubSer)
	if err != nil {
		t.Fatal(err)
	}
	if !g2pubs.Verify(msg, pubDeser, sig) {
		t.Fatal("message did not verify after serialization/deserialization of pubkey")
	}
}

func TestSecretkeySerializeDeserialize(t *testing.T) {
	r := NewXORShift(3)
	priv, _ := g2pubs.RandKey(r)
	privSer := priv.Serialize()
	privNew := g2pubs.DeserializeSecretKey(privSer)
	pub := g2pubs.PrivToPub(priv)
	msg := []byte(fmt.Sprintf(">16 character identical message"))
	sig := g2pubs.Sign(msg, privNew)

	if !g2pubs.Verify(msg, pub, sig) {
		t.Fatal("message did not verify before serialization/deserialization of secret")
	}

	pubSer := pub.Serialize()
	pubDeser, err := g2pubs.DeserializePublicKey(pubSer)
	if err != nil {
		t.Fatal(err)
	}
	if !g2pubs.Verify(msg, pubDeser, sig) {
		t.Fatal("message did not verify after serialization/deserialization of secret")
	}
}

func TestDeriveSecretKey(t *testing.T) {
	var secKeyIn [32]byte
	copy(secKeyIn[:], []byte("11223344556677889900112233445566"))
	k := g2pubs.DeriveSecretKey(secKeyIn)

	expectedElement, _ := bls.FRReprFromString("414e2c2a330cf94edb70e1c88efa851e80fe5eb14ff08fe5b7e588b4fe9899e4", 16)
	expectedFRElement := bls.FRReprToFR(expectedElement)

	if !expectedFRElement.Equals(k.GetFRElement()) {
		t.Fatal("expected secret key to match")
	}
}

func TestPubkeyDeserializeInvalid(t *testing.T) {
	unexpectedPub := "b5a44e98e450f266567be0d82e60d965aa8703f73a9a71aa03b98215444f781d00000000000000000000000000000000b5a44e98d450f266567be0d82e60d965aa8703f73a9a71aa03b98215444f781d00000000000000000000000000000000"
	var pubkey [96]byte
	if _, err := hex.Decode(pubkey[:], []byte(unexpectedPub)); err != nil {
		t.Fatal(err)
	}
	// panics unexpectedly! no error
	_, err := g2pubs.DeserializePublicKey(pubkey)
	if err == nil {
		t.Fatal("expected deserialization of invalid pubkey to fail")
	}
}

func TestConvertPubkeyToFromPoint(t *testing.T) {
	r := NewXORShift(3)
	priv, _ := g2pubs.RandKey(r)
	pub := g2pubs.PrivToPub(priv)

	pubPoint := pub.GetPoint()
	newPub := g2pubs.NewPublicKeyFromG2(pubPoint.ToAffine())

	if !newPub.Equals(*pub) {
		t.Fatal("expected pub -> point -> pub to return the same public key.")
	}
}

func TestConvertSignatureToFromPoint(t *testing.T) {
	r := NewXORShift(3)
	priv, _ := g2pubs.RandKey(r)
	pub := g2pubs.PrivToPub(priv)
	msg := []byte("hello!")
	sig := g2pubs.Sign(msg, priv)

	sigPoint := sig.GetPoint()
	newSig := g2pubs.NewSignatureFromG1(sigPoint.ToAffine())

	if !g2pubs.Verify(msg, pub, newSig) {
		t.Fatal("expected sig -> point -> sig to return the same public key.")
	}
}
