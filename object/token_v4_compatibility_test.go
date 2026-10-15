package object

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestV4IDTokenAndMFAProofCoexistAcrossFormats(t *testing.T) {
	setupStuHelperOAuthTestDatabase(t)
	_, err := AddCert(&Cert{Owner: "admin", Name: "synthetic-v4-cert", CryptoAlgorithm: "RS256", BitSize: 2048, ExpireInYears: 1})
	if err != nil {
		t.Fatal(err)
	}
	cert, err := getCert("admin", "synthetic-v4-cert")
	if err != nil {
		t.Fatal(err)
	}
	key, err := jwt.ParseRSAPublicKeyFromPEM([]byte(cert.Certificate))
	if err != nil {
		t.Fatal(err)
	}
	decode := func(raw string) jwt.MapClaims {
		t.Helper()
		claims := jwt.MapClaims{}
		_, err := jwt.ParseWithClaims(raw, claims, func(token *jwt.Token) (interface{}, error) { return key, nil }, jwt.WithValidMethods([]string{"RS256"}))
		if err != nil {
			t.Fatal(err)
		}
		return claims
	}
	for _, format := range []string{"JWT", "JWT-Empty", "JWT-Custom", "JWT-Standard"} {
		t.Run(format, func(t *testing.T) {
			application := &Application{Owner: "admin", Name: "synthetic-v4", ClientId: "synthetic-client", Cert: cert.Name, TokenFormat: format, ExpireInHours: 1, RefreshExpireInHours: 24}
			user := &User{Owner: "synthetic-org", Name: "Alice123", Id: "synthetic-subject"}
			proof := NewMFAAuthenticationContext("password", TotpType, 1712345678)
			options := jwtTokenOptions{AuthTime: 1712345680, StuHelperAuthz: "ag1:opaque:binding", Authentication: proof, Code: "synthetic-code", WithAtHash: true}
			access, refresh, idToken, _, err := generateJwtTokenWithOptions(application, user, "", "password", "nonce +&=", "openid offline_access", "https://resource.example", "sso.example", options)
			if err != nil {
				t.Fatal(err)
			}
			if access == idToken || access == refresh || idToken == refresh {
				t.Fatal("v4 token types must be independently signed")
			}
			accessClaims, refreshClaims, idClaims := decode(access), decode(refresh), decode(idToken)
			for name, claims := range map[string]jwt.MapClaims{"access-token": accessClaims, "refresh-token": refreshClaims, "id-token": idClaims} {
				if claims["tokenType"] != name || claims["stuhelper_authz"] != options.StuHelperAuthz || claims["nonce"] != "nonce +&=" || claims["acr"] != "mfa" || claims["auth_time"] != float64(proof.AuthTime) {
					t.Fatalf("lost token binding or MFA context in %s", name)
				}
				if !reflect.DeepEqual(claims["amr"], []interface{}{"pwd", "mfa", "totp"}) {
					t.Fatalf("lost authentication methods in %s", name)
				}
			}
			if idClaims["at_hash"] != getOidcHash(access, jwt.SigningMethodRS256) || idClaims["c_hash"] != getOidcHash(options.Code, jwt.SigningMethodRS256) {
				t.Fatal("ID token must retain the v4 access-token and code hashes")
			}
			idAudience, _ := idClaims.GetAudience()
			accessAudience, _ := accessClaims.GetAudience()
			if !reflect.DeepEqual(idAudience, jwt.ClaimStrings{application.ClientId}) || !reflect.DeepEqual(accessAudience, jwt.ClaimStrings{"https://resource.example"}) {
				t.Fatal("the resource audience must not replace the ID-token audience")
			}
			options.Authentication = nil
			access, _, _, _, err = generateJwtTokenWithOptions(application, user, "", "password", "", "openid", "", "sso.example", options)
			if err != nil {
				t.Fatal(err)
			}
			claims := decode(access)
			if claims["auth_time"] != float64(options.AuthTime) || claims["acr"] != nil || claims["amr"] != nil {
				t.Fatal("upstream credential auth_time must not invent MFA assurance")
			}
		})
	}
}

func TestV4AuthTimeHasOneNumericJSONField(t *testing.T) {
	raw, err := json.Marshal(Claims{User: &User{}, OidcIdTokenClaims: OidcIdTokenClaims{AuthTime: jwt.NewNumericDate(time.Unix(1712345678, 0))}})
	if err != nil {
		t.Fatal(err)
	}
	var claims map[string]interface{}
	if err := json.Unmarshal(raw, &claims); err != nil {
		t.Fatal(err)
	}
	if claims["auth_time"] != float64(1712345678) {
		t.Fatal("auth_time must retain its NumericDate wire representation")
	}
}
