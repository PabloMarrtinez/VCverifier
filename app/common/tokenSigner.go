package common

import (
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwt"
)

type TokenSigner interface {
	Sign(t jwt.Token, alg jwa.SignatureAlgorithm, key interface{}, options ...jwt.SignOption) ([]byte, error)
}

type JwtTokenSigner struct{}

func (JwtTokenSigner) Sign(t jwt.Token, alg jwa.SignatureAlgorithm, key interface{}, options ...jwt.SignOption) ([]byte, error) {
	return jwt.Sign(t, alg, key, options...)
}
