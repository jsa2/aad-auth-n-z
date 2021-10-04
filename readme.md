## Azure Service Authentication and Authorization table

This table is provided for reviewing service authentication and authorization security in Azure – Especially cross-service security. It has been made publicly available so it can be referred in any documentation as URL.

- [Azure Service Authentication and Authorization table](#azure-service-authentication-and-authorization-table)
  - [MS references](#ms-references)
  - [Notes regarding non AAD-based authentication options](#notes-regarding-non-aad-based-authentication-options)
  - [Notes regarding AAD-based authentication options](#notes-regarding-aad-based-authentication-options)
  - [Service Table](#service-table)
  - [Notes](#notes)
    - [SAS KEYS](#sas-keys)
    - [App registrations](#app-registrations)
    - [API management](#api-management)
    - [Require user assigment on applications by default and check permissions](#require-user-assigment-on-applications-by-default-and-check-permissions)
    - [Service connections in Azure Devops](#service-connections-in-azure-devops)
    - [Certificate option for client credentials](#certificate-option-for-client-credentials)
      - [Code examples of client credential with certificate](#code-examples-of-client-credential-with-certificate)
      - [Validation of certificate use by claims in token](#validation-of-certificate-use-by-claims-in-token)
- [Contribution](#contribution)
- [Disclaimer](#disclaimer)


### MS references 
MS recommendations below is just subset of many examples. I picked few ones which are really driving the point of trying to avoid password (string-based) options. 
  
 **⚠ The emphasis is to highlight the significance of choosing between Azure AD and non-Azure AD authentication options for Azure services.**

- [IM-2: Manage application identities securely and automatically](https://docs.microsoft.com/en-us/security/benchmark/azure/security-controls-v2-identity-management#im-2-manage-application-identities-securely-and-automatically)
- [Use Azure AD Authentication instead of SQL server authentication in Azure SQL](https://docs.microsoft.com/en-us/azure/security/fundamentals/paas-applications-using-sql)
- [Microsoft recommends using Azure AD with your Azure Service Bus applications when possible](https://docs.microsoft.com/en-us/azure/service-bus-messaging/service-bus-sas)
- [Azure AD provides superior security and ease of use over Shared Key for authorizing requests to Blob storage.](https://docs.microsoft.com/en-us/azure/storage/blobs/security-recommendations#identity-and-access-management)
- [Azure Event Hubs supports authorizing to Event Hubs resources using Azure Active Directory (Azure AD). Authorizing users or applications using OAuth 2.0 token returned by Azure AD provides superior security and ease of use over shared access signatures](https://docs.microsoft.com/en-us/azure/event-hubs/authorize-access-shared-access-signature#what-are-shared-access-signatures)
- [Configure your Azure API Management instance to protect your APIs by using the OAuth 2.0 protocol with Azure AD](https://docs.microsoft.com/en-us/security/benchmark/azure/baselines/api-management-security-baseline#311-monitor-attempts-to-access-deactivated-credentials)


**⚠ MS sources on string-based password auth**

- [While function keys can provide some mitigation for unwanted access, the only way to truly secure your function endpoints is by implementing positive authentication of clients accessing your functions.](https://docs.microsoft.com/en-us/azure/azure-functions/security-concepts#authenticationauthorization)
- [While it's convenient to use password secrets as a credential, we strongly recommend that you use x509 certificates as the only credential type for getting tokens for your application](https://docs.microsoft.com/en-us/azure/active-directory/develop/security-best-practices-for-app-registration#credential-configuration)
- [Access key appears in the URL](https://docs.microsoft.com/en-us/azure/logic-apps/logic-apps-http-endpoint?WT.mc_id=AZ-MVP-5003833#q-what-about-url-security)
- [Our suggestion is to enable Diagnostic Logging and Azure Defender where available and periodically rotate your keys. ](https://msrc-blog.microsoft.com/2021/08/27/update-on-vulnerability-in-the-azure-cosmos-db-jupyter-notebook-feature/)
  
____

### Notes regarding non AAD-based authentication options
- All string-based authentication methods in table below are considered **passwords**.

❌Password/String-based authentication is not considered strong in terms of strength, as shown in the table below. Even though security can be increased with password length, and password rotation.
  -   The table assumes rotation because password can be [leaked](https://msrc-blog.microsoft.com/2021/08/27/update-on-vulnerability-in-the-azure-cosmos-db-jupyter-notebook-feature/)

❌Bypasses  Azure AD logs means that no events are produced for the resource type in Azure AD logs when the authentication mechanism is used.

❌ Susceptible to sharing across multiple targets in the table means that the service allows human defined password (monkey/dog/cat/birthday) creation, thus allowing the admin to re-use passwords across systems
- Services which generate these passwords, and don't allow admins to input passwords are considered not shareable in the same sense (not all services in the table can be shared across systems, but can be shared across clients still)

    **Note: Even if the key is system generated, it can be obviously leaked** [If a SAS is leaked, it can be used by anyone who obtains it, which can potentially compromise resource utilizing SAS scheme](https://docs.microsoft.com/en-us/azure/service-bus-messaging/service-bus-sas#best-practices-when-using-sas)


### Notes regarding AAD-based authentication options

✔ Can be authorized based on Azure RBAC settings on services, and Azure AD roles granted for the API permissions

✔ Are logged in both Azure AD and service specific logs

✔ Can be managed as objects exposed in Azure AD and Azure RBAC (supports listing, filtering, policies and have specific properties which are exposed to configuration plane)

### Service Table 

- Column *Service logs* in table mean that there is logging option outside Azure, which typically includes the authentication information.

**Service**|Azure AD & RBAC based | Logged in Azure AD | Logged in service specific logs | Rotation needed | Strength | Tied to resource lifecycle
-|-|-|-|-|-|-
| [Managed Identity](https://docs.microsoft.com/en-us/azure/active-directory/managed-identities-azure-resources/overview#managed-identity-types) | ✅  | ✅ |✅ | ✅  Managed identities do not require rotation | ✅  **Strong** (Certificate based) | ✅ * When using system assigned managed identity 
| [Service Principal](https://docs.microsoft.com/en-us/azure/active-directory/develop/app-objects-and-service-principals#service-principal-object) (Password)  | ✅ | ✅ |✅ | Requires Rotation (supports expiration) | ❌Password based <br> *While it's convenient to use password secrets as a credential, we strongly recommend that you use x509 certificates as the only credential type for getting tokens for your application.* <a href=https://docs.microsoft.com/en-us/azure/active-directory/develop/security-best-practices-for-app-registration#credential-configuration> MS security-best-practices for Credential configuration <a> |  ❌ Suspectible to sharing across multiple targets (while not common, Azure AD ServicePrincipals support user created passwords, which can be shared, and can be weak in strength)
| [Service Principal](https://docs.microsoft.com/en-us/azure/active-directory/develop/app-objects-and-service-principals#service-principal-object)  (Certificate)  | ✅ | ✅  |✅ | Less need for rotation as the service newer exposes the private key when requesting access tokens from Azure AD, still users or service can leak the key (supports expiration) - The key can additionally be protected by password, before it's allowed to form JWT token | ✅  **Strong** (Certificate based) [cert options](#certificate-option-for-client-credentials)  |  ❌ (Same Private Key could be shared for multiple app registrations)| 
| [Storage Account key](https://docs.microsoft.com/en-us/azure/storage/common/storage-account-keys-manage?tabs=azure-portal#protect-your-access-keys)  | ❌ Bypasses Azure RBAC |❌ No AAD Log| ✅|Requires Rotation (❌Does not support expiration) |❌Password based |✅ 
|[SAS Tokens in Logic Apps](https://docs.microsoft.com/en-us/azure/logic-apps/logic-apps-securing-a-logic-app?tabs=azure-portal#generate-shared-access-signatures-sas)<br> [SAS Tokens in Storage Accounts](https://docs.microsoft.com/en-us/azure/storage/common/storage-sas-overview) <br> [SAS Tokens in Event Hubs](https://docs.microsoft.com/en-us/azure/event-hubs/authorize-access-shared-access-signature#what-are-shared-access-signatures)<br> [SAS Tokens in Service Bus](https://docs.microsoft.com/en-us/azure/service-bus-messaging/service-bus-sas) | ❌ Bypasses Azure RBAC | ❌ No AAD Log| ✅ | Requires Rotation ( [¹](#notes) supports expiration) | ❌Password based  |✅ 
| SSH Keys|  ❌ Bypasses Azure RBAC |❌ No AAD Log| ✅|  Can be rotated if needed (with PKI) |✅  **Strong** (Certificate based)  |❌ Suspectible to sharing across multiple targets 
| SSH Passwords|  ❌ Bypasses Azure RBAC |❌ No AAD Log |✅| Requires Rotation (Supports user expiration) |❌Password based   |❌ Suspectible to sharing across multiple targets
|[PAT Azure DataBricks ](https://docs.microsoft.com/en-us/azure/databricks/dev-tools/api/latest/authentication) <br>[PAT in Azure Devops](https://docs.microsoft.com/en-us/azure/devops/organizations/accounts/use-personal-access-tokens-to-authenticate)|  ❌ Bypasses Azure RBAC |❌ No AAD Log  |✅|   Requires Rotation (supports expiration) |❌Password based |✅ 
| [SQL Authentication](https://docs.microsoft.com/en-us/azure/azure-sql/database/security-overview#authentication)  |❌ Bypasses Azure RBAC |❌ No AAD Log | ✅|  Requires Rotation (supports expiration)  |❌Password based|❌ Suspectible to  sharing across multiple targets
| [APIM Subscription Key](https://docs.microsoft.com/en-us/azure/api-management/api-management-subscriptions#what-are-subscriptions)  |❌ Bypasses Azure RBAC | ❌ No AAD Log  |✅|  Requires Rotation  | ❌Password based  |✅ 
| [Function Access Keys](https://docs.microsoft.com/en-us/azure/azure-functions/security-concepts#function-access-keys)  |❌ Bypasses Azure RBAC | ❌ Bypasses Azure Azure AD log|✅ | Requires Rotation  | ❌Password based  |✅ 

### Notes

#### SAS KEYS

While SAS keys themselves support expiration, they are often derived from key that does not support expiration. Such  examples are the keys in the connection string of Event Hub and service hubs under shared access policies.

![img](img/SharedAccessPolicies.png)

![img](img/SharedAccessPoliciesK.png)

#### App registrations
App registrations are covered by the service principal scenarios in the table. See Service Principal and [types of service principal](https://docs.microsoft.com/en-us/azure/active-directory/develop/app-objects-and-service-principals#application-object) 


#### API management 
Ensure security operations such IP-filtering and authn/z related policies are required in **'All operations'** level. This ensures, that newly created operations will inherit the security policies of the API.
![img](img/APIM.png)

#### Require user assigment on applications by default and check permissions


- Attack scenario

This attack is possible against API's that don't check claims beyond the audience and issuer value for tokens issued to client credential enabled SPN's. Mitigation is to implement proper checking of claims, and/or requiring user assignment on the API. 
- Attacker is any SPN **registered** in the tenant which has client credentials registered.

![img](img/arbitrary%20SPN%20attack.png)

- Mitigation by proper claims checking

https://joonasw.net/view/always-check-token-permissions-in-aad-protected-api

- Mitigation by user assignment 

Requiring user assignment on Service Principal settings prevents arbitrary client credential enabled apps from being issued tokens with the correct audience for the attacker. The mitigation was originally proposed by [Johan Lindroos](https://www.linkedin.com/in/johanlindroos/)

✅ Setting on graph API
![img](img/SPN-UserAssignemtn.png)

✅ Setting on GUI
![img](img/SPN-UserAssignemtn1.png)

If this setting is not enabled arbitrary SPN's registered in the tenant with client credentials be they single or multi-tenant origin can request valid tokens for apps that don't do internal ACL for permissions (or require user assigment). 

- [Reference 1](https://joonasw.net/view/cross-tenant-token-attacks-now-harder-in-azure-ad)

*"But what if we did have an identity in the target tenant? If we could somehow trick a user in the organization to consent to our app, could we do the attack as before? Yes, we could. As long as a service principal for your app exists in the target tenant, you can acquire an access token for any API in that tenant."* 

- [Reference 2](https://joonasw.net/view/always-check-token-permissions-in-aad-protected-api)
![img](img/joonasw.png)



#### Service connections in Azure Devops
Security of service connections can be much enhanced by the use of managed identity (self-hosted Devops agent) - and SP (certificate) when MS-hosted pipeline is used.

- https://azsk.azurewebsites.net/09-AzureDevOps(VSTS)-Security/ControlCoverage/README.html#service-connection

- https://securecloud.blog/2021/04/13/azure-devops-use-certificate-for-azure-service-connection-spn/
![img](https://securecloud188323504.files.wordpress.com/2021/04/image-11.png)

#### Certificate option for client credentials
[*One form of credential that an application can use for authentication is a JSON Web Token (JWT) assertion signed with a certificate that the application owns.*](https://docs.microsoft.com/en-us/azure/active-directory/develop/active-directory-certificate-credentials)

##### Code examples of client credential with certificate
**NodeJS**
- [Azure AD Client Credentials with Certificate - Code Examples for Node.js](https://github.com/jsa2/aadClientCredWithCert#azure-ad-client-credentials-with-certificate---code-examples-for-nodejs)
- [service-principal and certificate based login by providing an ABSOLUTE file path to the .pem file](https://github.com/Azure/ms-rest-nodeauth#service-principal-and-certificate-based-login-by-providing-an-absolute-file-path-to-the-pem-file)
##### Validation of certificate use by claims in token
Any SP that uses certificate credential in client credential flow can be validated to have used the certificate after token validation by inspecting the ``appidacr`` claim.

https://securecloud.blog/2021/01/15/azure-api-management-enforce-use-of-certificate-in-client-credentials-flow/
![img](https://securecloud188323504.files.wordpress.com/2021/01/apim.png)


## Contribution
Feel free to submit pull request for fixing, or adding anything in this document 
  
## Disclaimer
The information in this document is provided “AS IS” with no warranties and confers no rights.
