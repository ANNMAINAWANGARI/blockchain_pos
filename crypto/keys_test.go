package crypto

import (
	
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGeneratePrivateKey(t *testing.T) {
  privKey := GeneratePrivateKey()
  assert.Equal(t, len(privKey.Bytes()),privKeyLen)
  pubKey :=privKey.Public()
  assert.Equal(t,len(pubKey.Bytes()),pubKeyLen)
}

func TestNewPrivateKeyFromString(t *testing.T){
	var(
		seed = "2584b8e72a2c5b639158b1014f83df1cc4882ce55f280d960bcde05fca5cc261"
	    privKey = NewPrivateKeyFromString(seed)
		addressStr = "e098692712786535e453646f8dc4a6e5e54d1e8f"
	)
	
	assert.Equal(t, privKeyLen, len(privKey.Bytes()))
	address := privKey.Public().Address()
	assert.Equal(t, addressStr, address.String())
	
}

func TestPrivateKeySign(t *testing.T){
	privKey := GeneratePrivateKey()
	pubKey :=privKey.Public()
	msg :=[]byte("foo bar baz")

	sig :=privKey.Sign(msg)
	assert.True(t, sig.Verify(pubKey,msg))
	//Test with invalid msg
	assert.False(t, sig.Verify(pubKey, []byte("foo")))

	//Test with invalid pubKey
	invalidPrivKey :=GeneratePrivateKey()
	invalidPubKey := invalidPrivKey.Public()
	assert.False(t, sig.Verify(invalidPubKey,msg))
}

func TestPublicKeyToAddress(t *testing.T){
	privKey := GeneratePrivateKey()
	pubKey :=privKey.Public()
	address := pubKey.Address()
	fmt.Println(address)
	assert.Equal(t,addressLen, len(address.Bytes()))
}