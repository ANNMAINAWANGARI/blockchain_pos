package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"io"
)

const (
	privKeyLen = 64
	pubKeyLen = 32
	seedLen = 32
	addressLen = 20
)

type PrivateKey struct {
	key ed25519.PrivateKey
}
 type PublicKey struct{
	key ed25519.PublicKey
 }
 type Signature struct{
	value []byte
 }
 type Address struct{
	value []byte
 }

 func GeneratePrivateKey() *PrivateKey{
	seed:=make([]byte,seedLen)
	_,err:=io.ReadFull(rand.Reader,seed)
	if err !=nil{
		panic(err)
	}
	return &PrivateKey{
		key: ed25519.NewKeyFromSeed(seed),
	}
 }

func (p *PrivateKey) Bytes() []byte{
	return p.key
}

func (p *PublicKey) Bytes() []byte{
	return p.key
}
func (s *Signature) Bytes() []byte{
	return s.value
}

func (p *PrivateKey) Sign(msg []byte) *Signature{
	return &Signature{
		value: ed25519.Sign(p.key, msg)}
}


func(s *Signature) Verify(pubKey *PublicKey, msg []byte) bool{
	return ed25519.Verify(pubKey.key, msg, s.value)
}

func (p *PrivateKey) Public() *PublicKey{
	b:=make([]byte, pubKeyLen)
	copy(b,p.key[32:])

	return &PublicKey{
		key:b,
	}
}

func(a Address) String() string{
	return hex.EncodeToString(a.value)
}

func (p *PublicKey) Address() Address{
	return Address{
		value: p.key[len(p.key)-addressLen:],
	}
}

func (a Address) Bytes() []byte {
	return a.value
}