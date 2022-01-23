## Azure Service Authentication and Authorization table

This table is provided for reviewing service authentication and authorization security in Azure – Especially cross-service security. It has been made publicly available so it can be referred in any documentation as URL.

- [Azure Service Authentication and Authorization table](#azure-service-authentication-and-authorization-table)
  - [MS references](#ms-references)
  - [Notes regarding non AAD-based authentication options](#notes-regarding-non-aad-based-authentication-options)
  - [Notes regarding AAD-based authentication options](#notes-regarding-aad-based-authentication-options)
  - [Service Table](#service-table)
  - [Notes](#notes)
    - [Fetching non-Azure AD based credentials with initial Azure AD authentication](#fetching-non-azure-ad-based-credentials-with-initial-azure-ad-authentication)
    - [App Service Deployment Credentials](#app-service-deployment-credentials)
      - [Bypassing Azure AD with indirect access to Azure Key Vault References](#bypassing-azure-ad-with-indirect-access-to-azure-key-vault-references)
      - [Secure the SCM endpoint for CI/CD](#secure-the-scm-endpoint-for-cicd)
    - [SAS KEYS](#sas-keys)
    - [App registrations](#app-registrations)
    - [API management](#api-management)
    - [Require user assigment on applications by default and check permissions](#require-user-assigment-on-applications-by-default-and-check-permissions)
    - [Azure DevOps - Ensure PAT tokens are evaluated with Conditional Access Policy (CAP) validation](#azure-devops---ensure-pat-tokens-are-evaluated-with-conditional-access-policy-cap-validation)
      - [FootNote](#footnote)
    - [Service connections in Azure Devops](#service-connections-in-azure-devops)
    - [Certificate option for client credentials](#certificate-option-for-client-credentials)
      - [Code examples of client credential with certificate](#code-examples-of-client-credential-with-certificate)
      - [Validation of certificate use by claims in token](#validation-of-certificate-use-by-claims-in-token)
    - [SQL authentication and 'Allow Azure services and resources to access this server'](#sql-authentication-and-allow-azure-services-and-resources-to-access-this-server)
- [SQL](#sql)
    - [Auditing local authentication with Azure Policy](#auditing-local-authentication-with-azure-policy)
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
| [Storage Account key](https://docs.microsoft.com/en-us/azure/storage/common/storage-account-keys-manage?tabs=azure-portal#protect-your-access-keys)  | ❌ Bypasses Azure RBAC [note ¹](#fetching-non-azure-ad-based-credentials-with-initial-azure-ad-authentication) |❌ No AAD Log| ✅|Requires Rotation (❌Does not support expiration) |❌Password based |✅ 

--- 
Table continues

**Service**|Azure AD & RBAC based | Logged in Azure AD | Logged in service specific logs | Rotation needed | Strength | Tied to resource lifecycle
-|-|-|-|-|-|-
|[SAS Tokens in Logic Apps](https://docs.microsoft.com/en-us/azure/logic-apps/logic-apps-securing-a-logic-app?tabs=azure-portal#generate-shared-access-signatures-sas)<br> [SAS Tokens in Storage Accounts](https://docs.microsoft.com/en-us/azure/storage/common/storage-sas-overview) <br> [SAS Tokens in Event Hubs](https://docs.microsoft.com/en-us/azure/event-hubs/authorize-access-shared-access-signature#what-are-shared-access-signatures)<br> [SAS Tokens in Service Bus](https://docs.microsoft.com/en-us/azure/service-bus-messaging/service-bus-sas) | ❌ Bypasses Azure RBAC [note ¹](#fetching-non-azure-ad-based-credentials-with-initial-azure-ad-authentication) | ❌ No AAD Log| ✅ | Requires Rotation ( [¹](#notes) supports expiration) | ❌Password based  |✅ 
| SSH Keys|  ❌ Bypasses Azure RBAC [note ¹](#fetching-non-azure-ad-based-credentials-with-initial-azure-ad-authentication) |❌ No AAD Log| ✅|  Can be rotated if needed (with PKI) |✅  **Strong** (Certificate based)  |❌ Suspectible to sharing across multiple targets 
| SSH Passwords|  ❌ Bypasses Azure RBAC [note ¹](#fetching-non-azure-ad-based-credentials-with-initial-azure-ad-authentication) |❌ No AAD Log |✅| Requires Rotation (Supports user expiration) |❌Password based   |❌ Suspectible to sharing across multiple targets
|[PAT Azure DataBricks ](https://docs.microsoft.com/en-us/azure/databricks/dev-tools/api/latest/authentication) <br>[PAT in Azure Devops](https://docs.microsoft.com/en-us/azure/devops/organizations/accounts/use-personal-access-tokens-to-authenticate)|  ❌ Bypasses Azure RBAC [note ¹](#fetching-non-azure-ad-based-credentials-with-initial-azure-ad-authentication) |❌ No AAD Log  |✅|   Requires Rotation (supports expiration) |❌Password based |✅ 
| [SQL Authentication](https://docs.microsoft.com/en-us/azure/azure-sql/database/security-overview#authentication)  |❌ Bypasses Azure RBAC [note ¹](#fetching-non-azure-ad-based-credentials-with-initial-azure-ad-authentication) |❌ No AAD Log | ✅|  Requires Rotation (supports expiration)  |❌Password based|❌ Suspectible to  sharing across multiple targets

--- 
Table continues

**Service**|Azure AD & RBAC based | Logged in Azure AD | Logged in service specific logs | Rotation needed | Strength | Tied to resource lifecycle
-|-|-|-|-|-|-
| [APIM Subscription Key](https://docs.microsoft.com/en-us/azure/api-management/api-management-subscriptions#what-are-subscriptions)  |❌ Bypasses Azure RBAC [note ¹](#fetching-non-azure-ad-based-credentials-with-initial-azure-ad-authentication) | ❌ No AAD Log  |✅|  Requires Rotation  | ❌Password based  |✅ 
| [Function Access Keys](https://docs.microsoft.com/en-us/azure/azure-functions/security-concepts#function-access-keys)  |❌ Bypasses Azure RBAC [note ¹](#fetching-non-azure-ad-based-credentials-with-initial-azure-ad-authentication) | ❌ Bypasses Azure Azure AD log|✅ | Requires Rotation  | ❌Password based  |✅ 
[App Service Webdeploy (Basic Auth)](https://docs.microsoft.com/en-us/azure/app-service/deploy-configure-credentials?tabs=cli#disable-basic-authentication) |❌ Bypasses Azure RBAC [note ¹](#fetching-non-azure-ad-based-credentials-with-initial-azure-ad-authentication) | ❌ No AAD Log  |✅|  Requires Rotation  | ❌Password based  |✅ 
[App Service Webdeploy (FTP)](https://docs.microsoft.com/en-us/azure/app-service/deploy-configure-credentials?tabs=cli#ftp) |❌ Bypasses Azure RBAC [note ¹](#fetching-non-azure-ad-based-credentials-with-initial-azure-ad-authentication) | ❌ No AAD Log  |✅|  Requires Rotation  | ❌Password based  |✅ 
[AKS management with ``--admin`` option](https://docs.microsoft.com/en-us/azure/aks/managed-aad#disable-local-accounts) | 📑 Initial sign-in is Azure RBAC when Azure RBAC is used | 📑 No AAD log after initial sign-in|✅ |Requires rotation [Rotate certificates in Azure Kubernetes Service (AKS)](https://docs.microsoft.com/en-us/azure/aks/certificate-rotation#aks-certificates-certificate-authorities-and-service-accounts) | ✅ Strong (Certificate based) |📑 Unlikely to be shared, as the AKS creates it's own CA


### Notes 

#### Fetching non-Azure AD based credentials with initial Azure AD authentication
To retrieve most of the credentials in the table you typically have to initially authenticate first with Azure AD. The table regurgitates the same scenario for many other credential types (Initially requires Azure AD but once obtained bypasses the access domain of Azure AD) - Scenarios like this means, that once the credential is fetched, it's issuance and usage are not tracked with Azure AD

#### App Service Deployment Credentials
To facilitate many of the deployment scenarios Azure App Service uses under the hood something called [Deployment Credentials](https://docs.microsoft.com/en-us/azure/app-service/deploy-configure-credentials?tabs=cli)

Essentially these credentials are used for two scenarios Basic auth string in authorization header ``Authorization: 'Basic YWRtaW5pc3RyYXRvcjpwYXNzd29yZA==``  for the SCM web api, and same deployment credentials FTP based, but passed in FTP protocol

##### Bypassing Azure AD with indirect access to Azure Key Vault References

⚠ Note: This bypass is based on **indirect access**. Azure Key Vault itself is not suspectible to non-azure-ad based access, and neither do the secrets exist outside runtime platform anywhere 

1. Attacker uses Basic Auth (publishingUserName and publishingPassword) to access directly key vault references that are loaded for runtime in the SCM API

**POC - Node.js**
```Javascript
async function mfaBypassToGetKeyVaultReferences(publishingUserName, publishingPassword, name) {
    var base64 = Buffer.from(`${publishingUserName}:${publishingPassword}`).toString('base64')
    var {data} = await axios({
        url:`https://${name}.scm.azurewebsites.net/api/settings`,
        headers: {
            "Authorization": "Basic " + base64},
            method:"get",
    }).catch((error) => console.log('sd')); console.log(data)
}
```
   
  **✅Credentials as Azure Key Vault Reference / Backed by Azure AD**
 ![img](img/depcred2.png)

   **⚠Access Key Vault References with basic auth if SCM endpoint is not secured**
  ![img](img/depcred.png)
 
##### Secure the SCM endpoint for CI/CD
Since many of the automations use these credentials, and publishing to app service does not directly support strong authentication supporting authorization mechnisms (Validation of JWT token in authorization header) it's important that once app is deployed you don't leave the endpoints open for exploitation. 
 
✅ Make securing non Azure AD backed endpoint part of your continous integration (If requested, I can add Azure Pipelines example)

**Options**
  
1. [Disable basic authentication](https://docs.microsoft.com/en-us/azure/app-service/deploy-configure-credentials?tabs=cli#disable-basic-authentication)
*Some organizations need to meet security requirements and would rather disable access via FTP or WebDeploy. This way, the organization's members can only access its App Services through APIs that are controlled by Azure Active Directory (Azure AD).*

2. [Network restriction on SCM endpoint](https://docs.microsoft.com/en-us/azure/azure-functions/security-concepts#secure-the-scm-endpoint)
*When you use network isolation to secure your functions, you must also account for this endpoint.*

---

#### SAS KEYS

While SAS keys themselves support expiration, they are often derived from key that does not support expiration. Such  examples are the keys in the connection string of Event Hub and service hubs under shared access policies.

![img](img/SharedAccessPolicies.png)

![img](img/SharedAccessPoliciesK.png)


Read more here https://docs.microsoft.com/en-us/azure/service-bus-messaging/service-bus-sas#shared-access-authorization-policies


---

#### App registrations
App registrations are covered by the service principal scenarios in the table. See Service Principal and [types of service principal](https://docs.microsoft.com/en-us/azure/active-directory/develop/app-objects-and-service-principals#application-object) 

---

#### API management 
Ensure security operations such IP-filtering and authn/z related policies are required in **'All operations'** level. This ensures, that newly created operations will inherit the security policies of the API.
![img](img/APIM.png)

---

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

If this setting is not enabled arbitrary SPN's registered in the tenant with client credentials(be they single or multi-tenant origin), the spn can request valid tokens for apps that don't do internal ACL for permissions (or require user assigment). 

- [Reference 1](https://joonasw.net/view/cross-tenant-token-attacks-now-harder-in-azure-ad)

*"But what if we did have an identity in the target tenant? If we could somehow trick a user in the organization to consent to our app, could we do the attack as before? Yes, we could. As long as a service principal for your app exists in the target tenant, you can acquire an access token for any API in that tenant."* 

- [Reference 2](https://joonasw.net/view/always-check-token-permissions-in-aad-protected-api)
![img](img/joonasw.png)

---

#### Azure DevOps - Ensure PAT tokens are evaluated with Conditional Access Policy (CAP) validation

![img](img/cap.png)

⚠ Carefully review and evaluate this control in test environment before enabling it on production

**MS references** [Microsoft Documentation](https://docs.microsoft.com/en-us/azure/devops/organizations/accounts/change-application-access-policies?view=azure-devops)

**Background**

Since the usage of PAT token is essentially basic auth, you might want to limit the usage of long-lived PAT's created for automations running outside Azure Devops. You can to this by enabling Conditional Access for non web-flows [¹](#footnote)  

[Personal Access Tokens and basic authentication](https://docs.microsoft.com/en-us/azure/devops/organizations/accounts/use-personal-access-tokens-to-authenticate?view=azure-devops&tabs=current-page#use-a-pat)
![img](img/devops-pat.png)


⚠ Beware that enabling IP-restrictions for PAT tokens affect also GIT clients that use short-lived PAT tokens after initial Azure AD authentication. Based on my testing usage of PAT tokens can't be excluded by advanced conditions like device filtering. Only IP and user exclusion seems to work. 
![img](img/pat3.PNG)

**Conditional Acces example**
Read [CA For PAT](guides/devopsCAP.md)

[*Azure AD Conditional Access is applied for the web flow regardless of this policy setting.*](https://docs.microsoft.com/en-us/azure/devops/organizations/accounts/change-application-access-policies?view=azure-devops#security-policies)

![img](img/patcap.png)


- There is also possibility of [restricting the lifetime of PAT tokens](https://docs.microsoft.com/en-us/azure/devops/release-notes/2021/sprint-188-update#restrict-personal-access-token-pat-scope-and-lifespan-via-azure-ad-tenant-policy), but this might require extensive work for long-running automations that do not use the build-agents built-in OAuth2 based flows and are excluded from CA based on 'named location' 
  - Automation would require PAT token renewal mechanism (That does not rely on another PAT token)
![img](img/leakedPAT.png)

**MS Documentation on the subject**

[Enable Azure Active Directory (Azure AD) Conditional Access Policy (CAP) validation](https://docs.microsoft.com/en-us/azure/devops/organizations/accounts/change-application-access-policies?view=azure-devops#security-policies)
- *this policy is set to off by default and only applies to other authentication methods aside from the web flow.*


##### FootNote 
¹ If you have 'all apps' type Conditional Access Policy, web flows are already protected by Conditional Access, regardless of the CAP setting in Azure Devops. Review carefully any PAT token usage, before enabling the policy: [example](guides/devopsCAP.md)

---

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


#### SQL authentication and 'Allow Azure services and resources to access this server'

 “Allow Azure services and resources to access this server” setting for SQL allows a trivial bypass for SQL firewall. Essentially the if attacker gets the SQL connection string, the protection by network rules does very little to protect from compromise, as the attacker can mount the attack from within Azure.

 - Many Azure Services rely on this setting to consume Azure SQL. Consider using this setting only if managed identities / Azure AD based identities are used to consume Azure SQL database. 
   
    Using Azure AD based identity based on strong authentcation to consume SQL ensures, that even if the firewall was bypassed, the attacker would need to get access tokens issued for the managed identity to continue the attack.

![img](/img/Allow%20Azure%20services%20and%20resources%20to%20access%20this%20server.png)


SQL
--- 

**MS reference**

*Switching the setting to ON creates an inbound firewall rule for IP 0.0.0.0 - 0.0.0.0 named AllowAllWindowsAzureIps*

[link](https://docs.microsoft.com/en-us/azure/azure-sql/database/firewall-configure#connections-from-inside-azure)

![img](img/sqldocsref.png)



#### Auditing local authentication with Azure Policy

Documentation [az policy set-definition](https://docs.microsoft.com/en-us/cli/azure/policy/set-definition?view=azure-cli-latest#az-policy-set-definition-create-examples)

Following AZ CLI command will deploy the policy initiative

```shell
az policy set-definition create -n Audit_Local_Authentication_Audit_Set \
--subscription '3539c2a2-cd25-48c6-b295-14e59334ef1c' \
--definitions https://raw.githubusercontent.com/jsa2/aad-auth-n-z/main/guides/localAuthPolicy/localAuthd.json

```
  
After running the Azure CLI command you should see following set displayed in Azure Policy. You can then proceed to assign the policy at scope you deem suitable 

![image](https://user-images.githubusercontent.com/58001986/150668653-d9809c1d-52aa-4bca-8e40-b361485c6ec3.png)


## Contribution
Feel free to submit pull request for fixing, or adding anything in this document 
  
## Disclaimer
The information in this document is provided “AS IS” with no warranties and confers no rights.
