package passkey

import "context"

// These callbacks run only after successful verification and credential persistence.
type AuthenticatedPrincipal struct {
	ID string `json:"id"`
}

type AuthenticationResult struct {
	Principal    AuthenticatedPrincipal `json:"principal"`
	CredentialID string                 `json:"credentialId"`
	PRFSupported bool                   `json:"prfSupported,omitempty"`
}

type RegistrationResult struct {
	Principal    AuthenticatedPrincipal `json:"principal"`
	CredentialID string                 `json:"credentialId"`
	PRFSupported bool                   `json:"prfSupported"`
}

type AuthenticationSuccessHandler interface {
	OnAuthenticated(context.Context, AuthenticationResult) error
}

type RegistrationSuccessHandler interface {
	OnRegistered(context.Context, RegistrationResult) error
}

type AuthenticationSuccessFunc func(context.Context, AuthenticationResult) error

func (f AuthenticationSuccessFunc) OnAuthenticated(ctx context.Context, result AuthenticationResult) error {
	return f(ctx, result)
}

type RegistrationSuccessFunc func(context.Context, RegistrationResult) error

func (f RegistrationSuccessFunc) OnRegistered(ctx context.Context, result RegistrationResult) error {
	return f(ctx, result)
}
