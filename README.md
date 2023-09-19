# DSBA PDP

[![FIWARE Security](https://nexus.lab.fiware.org/repository/raw/public/badges/chapters/security.svg)](https://www.fiware.org/developers/catalogue/)
[![License badge](https://img.shields.io/github/license/fiware/dsba-pdp.svg)](https://opensource.org/licenses/Apache-2.0)
[![Container Repository on Quay](https://img.shields.io/badge/quay.io-fiware%2Fdsba--pdp-grey?logo=red%20hat&labelColor=EE0000)](https://quay.io/repository/fiware/dsba-pdp)

Implementation of a Policy-Desicion Point, evaluating [Json-Web-Tokens](https://jwt.io/) containing VerifiableCredentials in an DSBA-compliant way. It also supports the evaluation in the context of [i4Trust](https://github.com/i4Trust).

## Quick start

The PDP will run in the context of an iShare-Dataprovider, therefor you need to supply the certificate and key, together with the client-id.
The certificate needs to be the full chain in pem-format, the key needs to be an unencrypted rsa-privatekey. See the (invalid!) examples in the [examples-folder](./examples/).   
The files need to be mounted to the container, default paths are /iShare/cert.pem and /iShare/key.pem. The Id has to be provided via the environment variable ```ISHARE_CLIENT_ID```. The default will use the authorization-registry at https://ar.isharetest.net .

Assuming the certificate and key for ```EU.EORI.NLPACKETDEL``` reside in $(pwd)/examples, a PDP for PacketDelivery can be started via

```
    docker run -v $(pwd)/examples:/iShare -e ISHARE_CLIENT_ID="EU.EORI.NLPACKETDEL" -p 8080:8080 quay.io/wi_stefan/dsba-pdp
```

The PDP is now available at ```localhost:8080``` and can be asked for a decision at ```localhost:8080/authz```
An example request would look like:

```
curl --location --request POST 'localhost:8080/authz' \
--header 'X-Original-URI: https://packetdelivery.org/ngsi-ld/v1/entities?type=DELIVERYORDER' \
--header 'X-Original-Action: GET' \
--header 'Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJkaWQ6ZWxzaTpwYWNrZXRkZWxpdmVyeSIsImlhdCI6MTY2NzU0NTExMiwiZXhwIjoxNjk5MDgxMTEyLCJhdWQiOiJFVS5FT1JJLk5MUEFDS0VFVERFTCIsInN1YiI6ImRpZDpwZWVyOjk5YWI1YmNhNDFiYjQ1Yjc4ZDI0MmE0NmYwMTU3YjdkIiwidmVyaWZpYWJsZUNyZWRlbnRpYWwiOnsiQGNvbnRleHQiOlsiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvdjEiLCJodHRwczovL2hhcHB5cGV0cy5maXdhcmUuaW8vMjAyMi9jcmVkZW50aWFscy9lbXBsb3llZS92MSJdLCJpZCI6Imh0dHBzOi8vaGFwcHlwZXRzLmZpd2FyZS5pby9jcmVkZW50aWFsLzI1MTU5Mzg5LThkZDE3Yjc5NmFjMCIsInR5cGUiOlsiVmVyaWZpYWJsZUNyZWRlbnRpYWwiLCJDdXN0b21lckNyZWRlbnRpYWwiXSwiaXNzdWVyIjp7ImlkIjoiZGlkOmVsc2k6aGFwcHlwZXRzIiwiaVNoYXJlSWQiOiJFVS5FT1JJLk5MSEFQUFlQRVRTIn0sImNyZWRlbnRpYWxTdWJqZWN0Ijp7ImlkIjoiZGlkOnBlZXI6OTlhYjViY2E0MWJiNDViNzhkMjQyYTQ2ZjAxNTdiN2QiLCJuYW1lIjoiVXNlckEiLCJnaXZlbl9uYW1lIjoiVXNlciIsImZhbWlseV9uYW1lIjoiQSIsInByZWZlcnJlZF91c2VybmFtZSI6InVzZXItYSIsImVtYWlsIjoidXNlckBhLm9yZyIsInJvbGVzIjpbeyJuYW1lIjoiU1RBTkRBUkRfQ1VTVE9NRVIiLCJhdXRob3JpemF0aW9uUmVnaXN0cnkiOnsiaWQiOiJFVS5FT1JJLk5MMDAwMDAwMDA0IiwiaG9zdCI6Imh0dHBzOi8vYXIuaXNoYXJldGVzdC5uZXQifX1dfX19.1Yj_EXVFPf1QE91VGusOiAaVUOlHYln2mNgYwMTxkNQ'
```

In this case, the user "UserA" of HappyPets has fullfilled the SIOP flow to PacketDelivery with a VP that includes the following VC, issued by HappyPets(encoded in the accesstoken above):
```json 
{
	"@context": [
		"https://www.w3.org/2018/credentials/v1",
		"https://happypets.fiware.io/2022/credentials/employee/v1"
	],
	"id": "https://happypets.fiware.io/credential/25159389-8dd17b796ac0",
	"type": [
		"VerifiableCredential",
		"CustomerCredential"
	],
	"issuer": "did:ebsi:happypets",
  "issuanceDate": "2022-11-23T15:23:13Z",
  "validFrom": "2022-11-23T15:23:13Z",
  "expirationDate": "2032-11-23T15:23:13Z",
	"credentialSubject": {
		"id": "did:peer:99ab5bca41bb45b78d242a46f0157b7d",
		"roles": [{
			"name": ["STANDARD_CUSTOMER"],
      "target": "did:ebsi:packetdelivery"
		}]
	}
}
```

With that information, the PDP will:

1. Build the policies required for the submitted request - e.g. GET https://packetdelivery.org/ngsi-ld/v1/entities?type=DELIVERYORDER
2. Iterates through the roles in the VC:
    1. Get and check the required policy for delegating the role from its own authorization-registry
    2. Get and check the policy connected with the assigned role from the authorization-registry included in the role
3. Return the decision

## Decision

The PDP will receive the contents of the credential in a trusted JWT, thus its already proofen that the issuer is allowed to issue the contained credential and claims.

Depending on the type of credential, the decider will then evaluate the request in the context of the VC. Currently, only the ```iShare-decider``` is implemented. Depending on the credentials type, the ```iShare-decider``` will use [iShare-compliant](https://dev.ishareworks.org) authoriation-registries to evaluate the request against the registered policies. 


# Configuration

The service provides the following configuration options:

| Name | Description | Default |
|------|-------------|---------|
|   SERVER_PORT  |       Port that the pdp will listen at. | ```8080```  |
|   JSON_LOGGING_ENABLED  |    Should the pdp log in json format? | ```true```  |
|   LOG_LEVEL  |    Log level to be used. | ```INFO```  |
|   LOG_REQUESTS  |    If enabled incoming requests will be logged. | ```true```  |
|   LOG_SKIP_PATHS  |    A comma seperated list of paths that should be excluded from request logging. |  |
|   ISHARE_ENABLED  |    Should the pdp use the iShare-authorization registry? | ```true```  |
|   ISHARE_TRUSTED_LIST_ENABLED  |    Should the pdp use the iShare-authorization registry as a trusted list? | ```true```  |
|   ISHARE_CERTIFICATE_PATH  |       Path to read the iShare certificate from. | ```/iShare/certificate.pem```  |
|   ISHARE_KEY_PATH  |       Path to read the iShare key from. | ```/iShare/key.pem```  |
|   ISHARE_CLIENT_ID  |       Id to be used for the IDP when interacting in iShare. | ```EU.EORI.MyDummyClient```  |
|   ISHARE_AR_ID  |       Id of the Authorization Registry to be used. | ```EU.EORI.NL000000004```  |
|   ISHARE_AUTHORIZATION_REGISTRY_URL  |       URL of the authorization registry. | ```https://ar.isharetest.net```  |
|   ISHARE_DELEGATION_PATH  |      Path to be used for making delegation requests at the AR. | ```/delegation```  |
|   ISHARE_TOKEN_PATH  |       Path to be used for making token requests at the AR. | ```/connect/token```  |
|   ISHARE_TRUSTED_FINGERPRINTS_LIST  | Initial list of fingerprints for trusted cas. This will be overwritten after the first update from the trust anchor. | ``````  |
|   ISHARE_TRUST_ANCHOR_URL  |  URL of the trust anchor service. | ```https://scheme.isharetest.net```  |
|   ISHARE_TRUST_ANCHOR_ID  |   ID of the trust anchor service. | ```EU.EORI.NL000000000```  |
|   ISHARE_TRUST_ANCHOR_TOKEN_PATH  |   Path to retrieve tokens from the trust anchor. | ```/connect/token```  |
|   ISHARE_TRUST_ANCHOR_TRUSTED_LIST_PATH  |   Path to retrieve the trusted list from the trust anchor. | ```/trusted_list```  |
|   ISHARE_TRUSTED_LIST_UPDATE_RATE  |  Frequncy of updates from the trust anchor. In s. | ```5```  |
|   PROVIDER_ID  |       ID to be used as a (default) role provider when verfiying the issuer. | ```did:ebsi:myprovider```  |
|   TRUSTED_VERIFIERS | Comma-seperated list of jwk-endpoints for the trusted verifiers(for verfiyng the incoming jwt.). Endpoints need to provide an [RFC-7517](https://www.rfc-editor.org/rfc/rfc7517#page-10) compatible JWKS. | `````` | 
|   JWK_UPDATE_INTERVAL_IN_S | Update interval of the cache in s. |  ```10``` |
