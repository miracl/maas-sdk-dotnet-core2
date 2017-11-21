# maas-sdk-dotnet-core2

[![Build status](https://ci.appveyor.com/api/projects/status/xf5ko4rj9og0mu62/branch/master?svg=true)](https://ci.appveyor.com/project/miraclops/maas-sdk-dotnet-core2/branch/master)
[![Coverage Status](https://coveralls.io/repos/github/miracl/maas-sdk-dotnet-core2/badge.svg?branch=master)](https://coveralls.io/github/miracl/maas-sdk-dotnet-core2?branch=master)

* **category**:    SDK
* **copyright**:   2017 MIRACL UK LTD
* **license**:     ASL 2.0 - http://www.apache.org/licenses/LICENSE-2.0
* **link**:        https://github.com/miracl/maas-sdk-dotnet-core2

## Description

.NET Core 2 version of the Software Development Kit (SDK) for MPin-As-A-Service (MAAS).

## Setup

1. Download or Clone the project
1. Open `Authentication.sln` with Visual Studio and build
1. Reference the `MiraclAuthentication` project in your ASP.NET project so you could authenticate to the MIRACL server

## Dependencies

MIRACL .NET Core2 SDK has the following dependencies:

1. .NET Core 2.0+ only
1.  MS Visual Studio 2017 and above

# Miracl API

## Details and usage for authentication

The authentication could be done either through the ASP.NET Core authentication mechanism or "manually" interacting with the SDK Api through a `MiraclClient` object.

### External authentication
To use the default authentication of the ASP.NET Core application with Miracl, user should use the following extension method where to specify his/her credentials to the Miracl Platform. 
```
services.AddAuthentication()
        .AddMiracl(Constants.AuthenticationScheme, o =>
        {
            o.ClientId = "CLIENT_ID";
            o.ClientSecret = "CLIENT_SECRET";
        });
```

### "Manual" Authentication 

#### Initialization
To start using Miracl API, `MiraclClient` should be initialized. It can be done when needed or at application startup. `MiraclOptions` class is used to pass the authentication credentials and parameters.

```
client = new MiraclClient(new MiraclOptions
{
    ClientId = "CLIENT_ID" ,
    ClientSecret = "CLIENT_SECRET",
    SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme,                     
    SaveTokens = true
});
```

`CLIENT_ID` and `CLIENT_SECRET` are obtained from MIRACL server and are unique per application. The authentication scheme has to be specified to be same as the one set in the `ConfigureServices` method of the application. If you need the tokens (access token, id token and refresh token), the `SaveTokens` property has to be set.

#### Authorization flow

If the user is not authorized, (s)he should scan the qr code with his/her phone app and authorize on the MIRACL server. This could be done as pass the authorize uri to the qr code by `ViewBag.AuthorizationUri = await client.GetAuthorizationRequestUrl(baseUri)` on the server and use it in the client with the following code:

```
<a id="btmpin"></a>

@section scripts{
<script src="<<Insert correct mpad url here>>" data-authurl="@ViewBag.AuthorizationUri" data-element="btmpin"></script>
}
```
Please refer to your distributor-specific documentation to find the correct url for the mpad.js `script src`.

When the user is being authorized, (s)he is returned to the `redirect uri` defined at creation of the application in the server. The redirect uri should be the same as the one used by the `MiraclClient` object (constructed by the appBaseUri + `CallbackPath` value of the `MiraclOptions` object by default).

To complete the authorization the query of the received request should be passed to `client.ValidateAuthorization(Request.Query)`. This method will return `AuthenticationProperties` of the response or throw exception if the token validation fails.

#### Status check and user data

If the user is authenticated `client.UserId` and `client.Email` will return additional user data after `client.GetIdentity(tokenResponse)` is executed which itself returns the claims-based identity for granting a user to be signed in.
If `null` is returned, the user is not authenticated or the token is expired and client needs to be authorized once more to access required data.

Use `client.ClearUserInfo(false)` to drop user identity data.

Use `client.ClearUserInfo()` to clear user authorization status.

#### Use PrerollId

In order to use PrerollId functionality in your web app, you should set `data-prerollid` parameter with the desired preroll id to the data element passed for authentication:
```	
<a id="{{buttonElementID}}" data-prerollid="{{prerollID}}></a>
```

In the current app this could be achieved with the following code:
```
<p>
	<a id="btmpin"></a>
</p>
<p>
	@Html.CheckBox("UsePrerollId") &nbsp; Use PrerollId login
	<div hidden="hidden">
		<label for="PrerollId" id="lblPrerollId">PrerollId</label>:
		<br />
		@Html.TextBox("PrerollId", string.Empty, new { style = "width:500px" })
	</div>
</p>

<script>
	$("#UsePrerollId").change(
	function () {
		var prerollIdContainer = $("#PrerollId").parent();
		prerollIdContainer.toggle();
		if (prerollIdContainer.is(":visible")) {
			$('#PrerollId').change(function (event) {
				var prerollIdData = document.getElementById('PrerollId').value;
				$('#btmpin').attr("data-prerollid", prerollIdData);
			});

		}
		else {
			$('#btmpin').removeAttr("data-prerollid");
		}
	});
</script>
```

#### DVS flow

DVS (designated verifier signature) scheme allows a client entity to sign a message/document (an important transaction) which could be verified only by the designated verifier. 
After the client (mobile) app generates the message, it sends it to the server (banking) which calls `MiraclClient.DvsCreateDocumentHash` method to create its hash using SHA256 hashing algorithm. Then the client app should create its signature and pass it to the server. The server has to create a `Signature` object and pass it to the `MiraclClient.DvsVerifySignature` method together with the epoch time (in seconds) of the signature creation (timestamp). The `MiraclClient` object retrieves the DVS Public Key from the MFA Platform where the DVS service runs and verifies the signature with it. The `Signature` object should have the following properties:
- `Hash` - the hash of the signed document 
- `MpinId` - the M-Pin ID used to generate the signature
- `U` - the random commitment generated by the user
- `V` - the proof of the signature
- `PublicKey` - the user public key used in the key-escrow less scheme. Only if key-escrow less scheme is supported.


## Samples

Replace `CLIENT_ID` and `CLIENT_SECRET` in the `appsettings.json` file with your valid credential data from the MIRACL server or use the [recommended approach](https://docs.microsoft.com/en-us/aspnet/core/security/app-secrets) by Microsoft. `baseUri` (which is passed to the `MiraclClient.GetAuthorizationRequestUrlAsync` method in the first sample) should be the uri of your web application.
Note that the redirect uri, if not explicitly specified in the `MiraclOptions`, is constructed as `baseUri\login` (the default value of the `CallbackPath` property is `\login`) and it should be passed to the MIRACL server when requiring authentication credential.

* `MiraclAuthenticationApp.Core2.0` demonstrates the usage of `MiraclClient` to authenticate to the MIRACL server

* `MiraclExternalAuthenticationApp.Core2.0` demonstrates external authentication to the Miracl server. The login page has a `MIRACL` button which performs the authentication. Note that the application uses a database which should be migrated before used.
In Visual Studio, you can use the Package Manager Console to apply pending migrations to the database by `PM> Update-Database`. Alternatively, you can apply pending migrations from a command prompt at your project directory by `> dotnet ef database update`. 


## Sample Endpoints 
The sample handles the following requests in order to serve as an authenticator for a mobile app:
* POST `/authzurl`
 This returns an http status of OK and data in the following json format:
```
{
    "authorizeURL": "<- The authorization url ->"
} 
```
* POST `/authtoken`
This endpoint authenticates by Authorization Code and User ID, passed in the following format:
```
{
    "code":"<- the authorization code to validate with ->",
    "userID":"<- the authorized email to be verified ->"
}
```
The http status code of the response corresponds to the status of the authentication. 

## Setting-up outbound HTTP Proxy Server

In order to make the SDK and the Sample Web App work using a proxy server, you should setup such using the Windows Internet configuration options:

1. Go to _Control Panel_ -> _Network and Internet_ -> _Internet Options_
1. Select the _Connections_ tab and the click the _LAN Settings_ button
1. Select the option _Use a proxy server for your LAN_ and specify the desired proxy server _Address_ and _Port_
1. Click the _OK_ button

After this configuration, the SDK and the Sample app should work through the specified proxy server.

## MIRACL .NET SDK Reference

 MIRACL .NET SDK library is based on the following libraries:

* [Microsoft.AspNetCore.Authentication.OpenIdConnect](https://www.nuget.org/packages/Microsoft.AspNetCore.Authentication.OpenIdConnect/)
