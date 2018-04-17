# Miracl Authentication Tests

## DVS integration test setup

The integration test uses [AppVeyor](https://www.appveyor.com) which internally sets the credential information for the test.
It also downloads [command line tool (mfaclient)](https://github.com/miracl/mfaclient) which is used for generating a signature for a sample document.
The mfaclient uses a [pluggable verification (PV) service](https://github.com/miracl/mfa-regex-verificator) in order to register a test identity.

To run the test locally you need to do the following steps:

1. Register on https://trust.miracl.cloud, setup `Fully Custom Verification` with `Push` notification type and set the `Verification URL` to where you will host the PV service
1. Build and run the [PV service](https://github.com/miracl/mfa-regex-verificator) and pass to it the `CustomerId` from https://trust.miracl.cloud
1. Create an app on https://trust.miracl.cloud and set the `Endpoint` field of DvsIntegrationTests.cs file to `https://api.mpin.io`
1. In `DvsIntegrationTests.cs` file set `ClientId`, `ClientSecret` and `ClientRedirectUri` to values corresponding to the app created above
1. Get `mfaclient.windows-amd64.tar.gz` from the latest release [here](https://github.com/miracl/mfaclient/releases) and unzip it
1. Add `mfaclient.exe` to the `MiraclAuthentication.Core2.0.Tests` directory
