# DBSA PDP

MVP implementation of a Policy-Desicion Point, defiend by the [DSBA-MVF](https://hesusruiz.github.io/dsbamvf).

## Quick start

The PDP will run in the context of an iShare-Dataprovider, therefor you need to supplie the certificate and key, together with the client-id.
The certificate needs to be the full chain in pem-format, the key needs to be an unencrypted rsa-privatekey. See the (invalid!) examples in the [examples-folder](./examples/).   
The files need to be mounted to the container, default paths are /iShare/cert.pem and /iShare/key.pem. The Id has to be provided via the environment variable ```ISHARE_CLIENT_ID``. The default will use the authorization-registry at https://ar.isharetest.net .

Assuming the certificate and key for ```EU.EORI.NLPACKETDEL``` reside in $(pwd)/examples, a PDP for PacketDelivery can be started via 

```
    docker run -v $(pwd)/examples:/iShare -e ISHARE_CLIENT_ID="EU.EORI.NLPACKETDEL" -p 8080:8080 dsba-pdp
```

The PDP is now available at ```localhost:8080``` and can be asked for a decision at ```localhost:8080/authz```
An example request would look like:

```
curl --location --request POST 'localhost:8080/authz' \
--header 'X-Original-URI: https://packetdelivery.org/ngsi-ld/v1/entities?type=DELIVERYORDER' \
--header 'X-Original-Action: GET' \
--header 'Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJkaWQ6ZWxzaTpwYWNrZXRkZWxpdmVyeSIsImlhdCI6MTY2NzU0NTExMiwiZXhwIjoxNjk5MDgxMTEyLCJhdWQiOiJFVS5FT1JJLk5MUEFDS0VFVERFTCIsInN1YiI6ImRpZDpwZWVyOjk5YWI1YmNhNDFiYjQ1Yjc4ZDI0MmE0NmYwMTU3YjdkIiwidmVyaWZpYWJsZUNyZWRlbnRpYWwiOnsiQGNvbnRleHQiOlsiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvdjEiLCJodHRwczovL2hhcHB5cGV0cy5maXdhcmUuaW8vMjAyMi9jcmVkZW50aWFscy9lbXBsb3llZS92MSJdLCJpZCI6Imh0dHBzOi8vaGFwcHlwZXRzLmZpd2FyZS5pby9jcmVkZW50aWFsLzI1MTU5Mzg5LThkZDE3Yjc5NmFjMCIsInR5cGUiOlsiVmVyaWZpYWJsZUNyZWRlbnRpYWwiLCJDdXN0b21lckNyZWRlbnRpYWwiXSwiaXNzdWVyIjp7ImlkIjoiZGlkOmVsc2k6aGFwcHlwZXRzIiwiaVNoYXJlSWQiOiJFVS5FT1JJLk5MSEFQUFlQRVRTIn0sImNyZWRlbnRpYWxTdWJqZWN0Ijp7ImlkIjoiZGlkOnBlZXI6OTlhYjViY2E0MWJiNDViNzhkMjQyYTQ2ZjAxNTdiN2QiLCJuYW1lIjoiVXNlckEiLCJnaXZlbl9uYW1lIjoiVXNlciIsImZhbWlseV9uYW1lIjoiQSIsInByZWZlcnJlZF91c2VybmFtZSI6InVzZXItYSIsImVtYWlsIjoidXNlckBhLm9yZyIsInJvbGVzIjpbeyJuYW1lIjoiU1RBTkRBUkRfQ1VTVE9NRVIiLCJhdXRob3JpemF0aW9uUmVnaXN0cnkiOnsiaWQiOiJFVS5FT1JJLk5MMDAwMDAwMDA0IiwiaG9zdCI6Imh0dHBzOi8vYXIuaXNoYXJldGVzdC5uZXQifX1dfX19.1Yj_EXVFPf1QE91VGusOiAaVUOlHYln2mNgYwMTxkNQ'
```
>:warning: The token is not verified in the current implementation, since its not yet fully specified. We assume the its already verified in an earlier stage.

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
	"issuer": {
		"id": "did:elsi:happypets",
		"iShareId": "EU.EORI.NLHAPPYPETS"
	},
	"credentialSubject": {
		"id": "did:peer:99ab5bca41bb45b78d242a46f0157b7d",
		"name": "UserA",
		"given_name": "User",
		"family_name": "A",
		"preferred_username": "user-a",
		"email": "user@a.org",
		"authorizationRegistry": {
			"id": "EU.EORI.NL000000004",
			"host": "https://ar.isharetest.net"
		},
		"roles": [{
			"name": "STANDARD_CUSTOMER"
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