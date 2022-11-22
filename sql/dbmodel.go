package sql

type TrustedIssuer struct {
	ID           string
	Capabilities []Capability `ref:"id" fk:"trusted_issuer" auto:"true"`
}

type Capability struct {
	ID              int
	ValidFrom       string
	ValidTo         string
	CredentialsType string
	Claims          []Claim `ref:"id" fk:"capability" auto:"true"`

	// ref to the issuer
	TrustedIssuerRef TrustedIssuer `ref:"trusted_issuer" fk:"id" auto:"true"`
	TrustedIssuer    string
}

type Claim struct {
	ID            int
	Name          string
	AllowedValues []AllowedValue `ref:"id" fk:"claim" auto:"true"`

	//ref to the capability
	CapabilityRef Capability `ref:"capability" fk:"id" auto:"true"`
	Capability    int
}

type AllowedValue struct {
	ID           int
	AllowedValue string

	//ref to the claim
	ClaimRef Claim `ref:"claim" fk:"id" auto:"true"`
	Claim    int
}
