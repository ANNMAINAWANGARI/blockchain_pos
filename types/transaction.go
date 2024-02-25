package types

import (
	"crypto/sha256"

	"github.com/ANNMAINAWANGARI/blockchain_pos01/crypto"
	"github.com/ANNMAINAWANGARI/blockchain_pos01/proto"
	pb "google.golang.org/protobuf/proto"
)

func HashTransaction(tx *proto.Transaction) []byte{
	b, err:= pb.Marshal(tx)
	if err!=nil{
		panic(err)
	}
	//sha256 returns an array
	hash :=sha256.Sum256(b)
	//convert to slice
	return hash[:]
}

func SignTransaction(pk *crypto.PrivateKey, tx *proto.Transaction) *crypto.Signature{
	return pk.Sign(HashTransaction(tx))
}

func VerifyTransaction(tx *proto.Transaction) bool{
	for _,input := range tx.Inputs{
		sig := crypto.SignatureFromBytes(input.Signature)
		input.Signature = nil
		if !sig.Verify(crypto.PublicKeyFromBytes(input.PublicKey),HashTransaction(tx)){
			return false
		}
	}
	return true
}