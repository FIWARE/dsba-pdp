# DSBA PDP

MVP implementation of a Policy-Desicion Point, defiend by the [DSBA-MVF](https://hesusruiz.github.io/dsbamvf).

## Quick start

The PDP will run in the context of an iShare-Dataprovider, therefor you need to supply the certificate and key, together with the client-id.
The certificate needs to be the full chain in pem-format, the key needs to be an unencrypted rsa-privatekey. See the (invalid!) examples in the [examples-folder](./examples/).   
The files need to be mounted to the container, default paths are /iShare/cert.pem and /iShare/key.pem. The Id has to be provided via the environment variable ```ISHARE_CLIENT_ID``. The default will use the authorization-registry at https://ar.isharetest.net .

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

1. Check that the issuer is allowed to assing the role ```STANDARD_CUSTOMER```, see the [trusted-list API](./api/trustedlist.yaml)
2. Build the policies required for the submitted request - e.g. GET https://packetdelivery.org/ngsi-ld/v1/entities?type=DELIVERYORDER
3. Iterates through the roles in the VC:
    1. Get and check the required policy for delegating the role from its own authorization-registry
    2. Get and check the policy connected with the assigned role from the authorization-registry included in the role
3. Return the decision

## Structure

The PDP evaluates the VerifiableCredential in 2 steps:

1. Trusted Issuer

The VerifiableCredential will be checked against the "trusted-issuers" list(see the [API](./api/trustedlist.yaml)). The list contains information about the types of credentials that are supported for certain issuers and the claims they can include into the credentials. 
In case of the [Quickstart-Example](#quick-start), the following configuration for the issuer will be required:
```json
{
  // id of the issuer	
  "id": "did:elsi:happypets",
  // the capabilities of the issuer, there can be multiple for example allowing different capabilities at different points of time
  "capabilities": [
    {
	  // validity of the capability
      "validFor": {
        "from": "2017-07-21T17:32:28Z",
        "to": "2033-07-21T17:32:28Z"
      },
	  // type of credentials allowed by this capability
      "credentialsType": "CustomerCredential",
	  // claims allowed for the given credential
      "claims": [
        {
          "name": "roles",
          "allowedValues": [
            "GOLD_CUSTOMER",
            "STANDARD_CUSTOMER"
          ]
        }
      ],
	  // specific policies to evalutate - not implemented yet
      "policy": {}
    }
  ]
}
```
The ```trusted-issuer``` consists of its ID and a list of capabilities. The capabilities describe the types of credentials an Issuer is allowed to issue and the claims it can use. The trusted-issuer check will "trust" the issuer if one of the capabilities can be successfully validated.

The current implementation supports of VerifiableCredentials of type ```CustomerCredential```. The credential can either include plain role information, where the role is resolved in the context of the local AuthorizationRegistry. The credential will be checked if the assigned roles are allowed for the given issuer.
If the optional information ```authorizationRegistries``` and ```role.provider``` is set in the VC, it will also be checked if the ARs are allowed and if the provider is allowed to be used for the role.
Such a VC will look as following:

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
    "authorizationRegistry": {
      "EU.EORI.HAPPYPETS": {
          "host": "http://keyrock:6080",
          "tokenPath": "/oauth2/token",
          "delegationPath": "/ar/delegation"
      }
    },
		"roles": [{
      "name": ["GOLD_CUSTOMER"],
      "target": "did:ebsi:packetdelivery",
      "provider": "EU.EORI.HAPPYPETS"
		}]
	}
}
```

2. Decider

Depending on the type of credential, the decider will now evaluate the request in the context of the VC. Currently, only the ```iShare-decider``` is implemented. Depending on the credentials type, the ```iShare-decider``` will use [iShare-compliant](https://dev.ishareworks.org) authoriation-registries to evaluate the request against the registered policies. 


# Configuration

The service provides the following configuration options:

| Name | Description | Default |
|------|-------------|---------|
|   MYSQL_HOST   |       Hostname of the MySql DB      | ```localhost``` |
|   MYSQL_PORT   |       Port of the MySql DB      | ```3306``` |
|   MYSQL_DATABASE   |       Schema to be used0     |  ```dsba``` |
|   MYSQL_USERNAME   |       Username to be used for the MySql DB      | ```root``` |
|   MYSQL_PASSWORD   |       Password to be used for the MySql DB      |  |


# Persistence

To run the trusted issuer service with persistence, provide the following ENV-Vars:

| Name | Description | Default |
|------|-------------|---------|
|   SERVER_PORT  |       Port that the pdp will listen at. | ```8080```  |
|   JSON_LOGGING_ENABLED  |    Should the pdp log in json format? | ```true```  |
|   LOG_LEVEL  |    Log level to be used. | ```INFO```  |
|   LOG_REQUESTS  |    If enabled incoming requests will be logged. | ```true```  |
|   LOG_SKIP_PATHS  |    A comma seperated list of paths that should be excluded from request logging. |  |
|   ISHARE_ENABLED  |    Should the pdp use the iShare-authorization registry? | ```true```  |
|   ISHARE_CERTIFICATE_PATH  |       Path to read the iShare certificate from. | ```/iShare/certificate.pem```  |
|   ISHARE_KEY_PATH  |       Path to read the iShare key from. | ```/iShare/key.pem```  |
|   ISHARE_CLIENT_ID  |       Id to be used for the IDP when interacting in iShare. | ```EU.EORI.MyDummyClient```  |
|   ISHARE_AR_ID  |       Id of the Authorization Registry to be used. | ```EU.EORI.NL000000004```  |
|   ISHARE_AUTHORIZATION_REGISTRY_URL  |       URL of the authorization registry. | ```https://ar.isharetest.net```  |
|   ISHARE_DELEGATION_PATH  |      Path to be used for making delegation requests at the AR. | ```/delegation```  |
|   ISHARE_TOKEN_PATH  |       Path to be used for making token requests at the AR. | ```/connect/token```  |
|   PROVIDER_ID  |       ID to be used as a (default) role provider when verfiying the issuer. | ```did:ebsi:myprovider```  |
|   MYSQL_HOST   |       Hostname of the MySql DB      | ```localhost``` |
|   MYSQL_PORT   |       Port of the MySql DB      | ```3306``` |
|   MYSQL_DATABASE   |       Schema to be used     |  ```dsba``` |
|   MYSQL_USERNAME   |       Username to be used for the MySql DB      | ```root``` |
|   MYSQL_PASSWORD   |       Password to be used for the MySql DB      |  |

In order to setup the schema, run the db-migrations container, configurable with the same environment-variables:

```shell
  docker run quay.io/wi_stefan/dsba-db-migrations rel migrate
```
