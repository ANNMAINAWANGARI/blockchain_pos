package types

import (
	"crypto/sha256"

	"github.com/ANNMAINAWANGARI/blockchain_pos01/crypto"
	"github.com/ANNMAINAWANGARI/blockchain_pos01/proto"
	pb "google.golang.org/protobuf/proto"
)

//Hashblock creates a SHA256 of the header
func HashBlock(block *proto.Block) []byte{
	b,err := pb.Marshal(block)
	if err!= nil{
		panic(err)
	}
	//sha256 returns an array
	hash :=sha256.Sum256(b)
	//convert to slice
	return hash[:]
}

func SignBlock(pk *crypto.PrivateKey, b *proto.Block) *crypto.Signature{
	return pk.Sign(HashBlock(b))
}