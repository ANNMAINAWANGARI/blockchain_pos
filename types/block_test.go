package types

import (
	"testing"

	"github.com/ANNMAINAWANGARI/blockchain_pos01/crypto"
	"github.com/ANNMAINAWANGARI/blockchain_pos01/util"
	"github.com/stretchr/testify/assert"
)


func TestHashBlock(t *testing.T){
	block:= util.RandomBlock()
	hash := HashBlock(block)
	assert.Equal(t, len(hash),32)
}

func TestSignBlock(t *testing.T){
	block:= util.RandomBlock()
	privKey := crypto.GeneratePrivateKey()
	pubKey := privKey.Public()
	sig := SignBlock(privKey,block)
	assert.Equal(t, 64, len(sig.Bytes()))
	assert.True(t,sig.Verify(pubKey,HashBlock(block)))
}