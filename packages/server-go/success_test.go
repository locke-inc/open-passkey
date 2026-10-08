package passkey_test

import (
	"context"
	"net/http"
	"testing"

	passkey "github.com/locke-inc/open-passkey/packages/server-go"
)

func TestSuccessCallbacksFollowVerifiedCeremonies(t *testing.T) {
	var registered passkey.RegistrationResult
	var authenticated passkey.AuthenticationResult
	registerCalls, authCalls := 0, 0
	p, err := passkey.New(passkey.Config{RPID: "example.com", Origin: "https://example.com", ChallengeStore: passkey.NewMemoryChallengeStore(), CredentialStore: passkey.NewMemoryCredentialStore(), OnRegistered: passkey.RegistrationSuccessFunc(func(_ context.Context, r passkey.RegistrationResult) error {
		registered = r
		registerCalls++
		return nil
	}), OnAuthenticated: passkey.AuthenticationSuccessFunc(func(_ context.Context, r passkey.AuthenticationResult) error {
		authenticated = r
		authCalls++
		return nil
	})})
	if err != nil {
		t.Fatal(err)
	}
	key := mustP256Key(t)
	challenge := uvBeginReg(t, p, "callback-person", "required")
	id, cd, att := uvRegCeremony(t, key, challenge, true)
	resp := uvFinishReg(t, p, "callback-person", id, cd, att)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK || registerCalls != 1 || registered.Principal.ID != "callback-person" || registered.CredentialID != id {
		t.Fatalf("registration callback missing: status=%d result=%+v", resp.StatusCode, registered)
	}
	begin := postJSON(p.BeginAuthentication, map[string]string{"userId": "callback-person", "userVerification": "required"})
	challenge = decodeResponse(t, begin)["challenge"].(string)
	cd, ad, sig := uvAuthCeremony(t, key, challenge, true, 1)
	body := map[string]any{"userId": "callback-person", "credential": map[string]any{"id": id, "rawId": id, "type": "public-key", "response": map[string]string{"clientDataJSON": cd, "authenticatorData": ad, "signature": sig}}}
	result := postJSON(p.FinishAuthentication, body)
	if result.Code != http.StatusOK || authCalls != 1 || authenticated.Principal.ID != "callback-person" || authenticated.CredentialID != id {
		t.Fatalf("authentication callback missing: %d %+v %s", result.Code, authenticated, result.Body.String())
	}
	replay := postJSON(p.FinishAuthentication, body)
	if replay.Code == http.StatusOK || authCalls != 1 {
		t.Fatal("failed ceremony fired a success callback")
	}
}
