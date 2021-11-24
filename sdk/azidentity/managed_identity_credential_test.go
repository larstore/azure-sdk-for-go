// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package azidentity

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/internal/mock"
	"github.com/Azure/azure-sdk-for-go/sdk/internal/recording"
)

const (
	appServiceWindowsSuccessResp = `{"access_token": "new_token", "expires_on": "9/14/2017 00:00:00 PM +00:00", "resource": "https://vault.azure.net", "token_type": "Bearer"}`
	appServiceLinuxSuccessResp   = `{"access_token": "new_token", "expires_on": "09/14/2017 00:00:00 +00:00", "resource": "https://vault.azure.net", "token_type": "Bearer"}`
	expiresOnIntResp             = `{"access_token": "new_token", "refresh_token": "", "expires_in": "", "expires_on": "1560974028", "not_before": "1560970130", "resource": "https://vault.azure.net", "token_type": "Bearer"}`
	expiresOnNonStringIntResp    = `{"access_token": "new_token", "refresh_token": "", "expires_in": "", "expires_on": 1560974028, "not_before": "1560970130", "resource": "https://vault.azure.net", "token_type": "Bearer"}`
)

// TODO: replace with 1.17's T.Setenv
func clearEnvVars(envVars ...string) {
	for _, ev := range envVars {
		_ = os.Unsetenv(ev)
	}
}

// A simple fake IMDS. Similar to mock.Server but doesn't wrap httptest.Server. That's
// important because IMDS is at 169.254.169.254, not httptest.Server's default 127.0.0.1.
type mockIMDS struct {
	resp []http.Response
}

func newMockImds(responses ...http.Response) (m *mockIMDS) {
	return &mockIMDS{resp: responses}
}

func (m *mockIMDS) Do(req *http.Request) (*http.Response, error) {
	if len(m.resp) > 0 {
		resp := m.resp[0]
		m.resp = m.resp[1:]
		return &resp, nil
	}
	panic("no more responses")
}

// delayPolicy adds a delay to pipeline requests. Used to test timeout behavior.
type delayPolicy struct {
	delay time.Duration
}

func (p delayPolicy) Do(req *policy.Request) (resp *http.Response, err error) {
	time.Sleep(p.delay)
	return req.Next()
}

func TestManagedIdentityCredential_GetTokenInAzureArcLive(t *testing.T) {
	if len(os.Getenv(arcIMDSEndpoint)) == 0 {
		t.Skip()
	}
	msiCred, err := NewManagedIdentityCredential(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	_, err = msiCred.GetToken(context.Background(), policy.TokenRequestOptions{Scopes: []string{liveTestScope}})
	if err != nil {
		t.Fatalf("Received an error when attempting to retrieve a token")
	}
}

func TestManagedIdentityCredential_GetTokenInCloudShellLive(t *testing.T) {
	if len(os.Getenv("MSI_ENDPOINT")) == 0 {
		t.Skip()
	}
	msiCred, err := NewManagedIdentityCredential(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	_, err = msiCred.GetToken(context.Background(), policy.TokenRequestOptions{Scopes: []string{liveTestScope}})
	if err != nil {
		t.Fatalf("Received an error when attempting to retrieve a token")
	}
}

func TestManagedIdentityCredential_GetTokenInCloudShellMock(t *testing.T) {
	resetEnvironmentVarsForTest()
	srv, close := mock.NewServer()
	defer close()
	srv.AppendResponse(mock.WithBody([]byte(accessTokenRespSuccess)))
	_ = os.Setenv("MSI_ENDPOINT", srv.URL())
	defer clearEnvVars("MSI_ENDPOINT")
	options := ManagedIdentityCredentialOptions{}
	options.Transport = srv
	msiCred, err := NewManagedIdentityCredential(&options)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	_, err = msiCred.GetToken(context.Background(), policy.TokenRequestOptions{Scopes: []string{liveTestScope}})
	if err != nil {
		t.Fatalf("Received an error when attempting to retrieve a token")
	}
}

func TestManagedIdentityCredential_GetTokenInCloudShellMockFail(t *testing.T) {
	resetEnvironmentVarsForTest()
	srv, close := mock.NewServer()
	defer close()
	srv.AppendResponse(mock.WithStatusCode(http.StatusUnauthorized))
	_ = os.Setenv("MSI_ENDPOINT", srv.URL())
	defer clearEnvVars("MSI_ENDPOINT")
	options := ManagedIdentityCredentialOptions{}
	options.Transport = srv
	msiCred, err := NewManagedIdentityCredential(&options)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	_, err = msiCred.GetToken(context.Background(), policy.TokenRequestOptions{Scopes: []string{liveTestScope}})
	if err == nil {
		t.Fatalf("Expected an error but did not receive one")
	}
}

func TestManagedIdentityCredential_GetTokenInAppServiceV20170901Mock_windows(t *testing.T) {
	resetEnvironmentVarsForTest()
	srv, close := mock.NewServer()
	defer close()
	srv.AppendResponse(mock.WithBody([]byte(appServiceWindowsSuccessResp)))
	_ = os.Setenv("MSI_ENDPOINT", srv.URL())
	_ = os.Setenv("MSI_SECRET", "secret")
	defer clearEnvVars("MSI_ENDPOINT", "MSI_SECRET")
	options := ManagedIdentityCredentialOptions{}
	options.Transport = srv
	msiCred, err := NewManagedIdentityCredential(&options)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	tk, err := msiCred.GetToken(context.Background(), policy.TokenRequestOptions{Scopes: []string{liveTestScope}})
	if err != nil {
		t.Fatalf("Received an error when attempting to retrieve a token")
	}
	if tk.Token != "new_token" {
		t.Fatalf("Did not receive the correct token. Expected \"new_token\", Received: %s", tk.Token)
	}
	if msiCred.client.msiType != msiTypeAppServiceV20170901 {
		t.Fatalf("Failed to detect the correct MSI Environment. Expected: %d, Received: %d", msiTypeAppServiceV20170901, msiCred.client.msiType)
	}
}

func TestManagedIdentityCredential_GetTokenInAppServiceV20170901Mock_linux(t *testing.T) {
	resetEnvironmentVarsForTest()
	srv, close := mock.NewServer()
	defer close()
	srv.AppendResponse(mock.WithBody([]byte(appServiceLinuxSuccessResp)))
	_ = os.Setenv("MSI_ENDPOINT", srv.URL())
	_ = os.Setenv("MSI_SECRET", "secret")
	defer clearEnvVars("MSI_ENDPOINT", "MSI_SECRET")
	options := ManagedIdentityCredentialOptions{}
	options.Transport = srv
	msiCred, err := NewManagedIdentityCredential(&options)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	tk, err := msiCred.GetToken(context.Background(), policy.TokenRequestOptions{Scopes: []string{liveTestScope}})
	if err != nil {
		t.Fatalf("Received an error when attempting to retrieve a token")
	}
	if tk.Token != "new_token" {
		t.Fatalf("Did not receive the correct token. Expected \"new_token\", Received: %s", tk.Token)
	}
	if msiCred.client.msiType != msiTypeAppServiceV20170901 {
		t.Fatalf("Failed to detect the correct MSI Environment. Expected: %d, Received: %d", msiTypeAppServiceV20170901, msiCred.client.msiType)
	}
}

func TestManagedIdentityCredential_GetTokenInAppServiceV20190801Mock_windows(t *testing.T) {
	t.Skip("App Service 2019-08-01 isn't supported because it's unavailable in some Functions apps.")
	resetEnvironmentVarsForTest()
	srv, close := mock.NewServer()
	defer close()
	srv.AppendResponse(mock.WithBody([]byte(appServiceWindowsSuccessResp)))
	_ = os.Setenv("IDENTITY_ENDPOINT", srv.URL())
	_ = os.Setenv("IDENTITY_HEADER", "header")
	defer clearEnvVars("IDENTITY_ENDPOINT", "IDENTITY_HEADER")
	options := ManagedIdentityCredentialOptions{}
	options.Transport = srv
	msiCred, err := NewManagedIdentityCredential(&options)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	tk, err := msiCred.GetToken(context.Background(), policy.TokenRequestOptions{Scopes: []string{liveTestScope}})
	if err != nil {
		t.Fatalf("Received an error when attempting to retrieve a token")
	}
	if tk.Token != "new_token" {
		t.Fatalf("Did not receive the correct token. Expected \"new_token\", Received: %s", tk.Token)
	}
	if msiCred.client.msiType != msiTypeAppServiceV20190801 {
		t.Fatalf("Failed to detect the correct MSI Environment. Expected: %d, Received: %d", msiTypeAppServiceV20190801, msiCred.client.msiType)
	}
}

func TestManagedIdentityCredential_GetTokenInAppServiceV20190801Mock_linux(t *testing.T) {
	t.Skip("App Service 2019-08-01 isn't supported because it's unavailable in some Functions apps.")
	resetEnvironmentVarsForTest()
	srv, close := mock.NewServer()
	defer close()
	srv.AppendResponse(mock.WithBody([]byte(appServiceLinuxSuccessResp)))
	_ = os.Setenv("IDENTITY_ENDPOINT", srv.URL())
	_ = os.Setenv("IDENTITY_HEADER", "header")
	defer clearEnvVars("IDENTITY_ENDPOINT", "IDENTITY_HEADER")
	options := ManagedIdentityCredentialOptions{}
	options.Transport = srv
	msiCred, err := NewManagedIdentityCredential(&options)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	tk, err := msiCred.GetToken(context.Background(), policy.TokenRequestOptions{Scopes: []string{liveTestScope}})
	if err != nil {
		t.Fatalf("Received an error when attempting to retrieve a token")
	}
	if tk.Token != "new_token" {
		t.Fatalf("Did not receive the correct token. Expected \"new_token\", Received: %s", tk.Token)
	}
	if msiCred.client.msiType != msiTypeAppServiceV20190801 {
		t.Fatalf("Failed to detect the correct MSI Environment. Expected: %d, Received: %d", msiTypeAppServiceV20190801, msiCred.client.msiType)
	}
}

// Azure Functions on linux environments currently doesn't properly support the identity header,
// therefore, preference must be given to the legacy MSI_ENDPOINT variable.
func TestManagedIdentityCredential_GetTokenInAzureFunctions_linux(t *testing.T) {
	resetEnvironmentVarsForTest()
	srv, close := mock.NewServer()
	defer close()
	srv.AppendResponse(mock.WithBody([]byte(appServiceWindowsSuccessResp)))
	_ = os.Setenv("MSI_ENDPOINT", srv.URL())
	_ = os.Setenv("MSI_SECRET", "secret")
	defer clearEnvVars("MSI_ENDPOINT", "MSI_SECRET")
	_ = os.Setenv("IDENTITY_ENDPOINT", srv.URL())
	_ = os.Setenv("IDENTITY_HEADER", "header")
	defer clearEnvVars("IDENTITY_ENDPOINT", "IDENTITY_HEADER")
	msiCred, err := NewManagedIdentityCredential(&ManagedIdentityCredentialOptions{ClientOptions: azcore.ClientOptions{Transport: srv}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	tk, err := msiCred.GetToken(context.Background(), policy.TokenRequestOptions{Scopes: []string{liveTestScope}})
	if err != nil {
		t.Fatalf("Received an error when attempting to retrieve a token")
	}
	if tk.Token != "new_token" {
		t.Fatalf("Did not receive the correct token. Expected \"new_token\", Received: %s", tk.Token)
	}
	if msiCred.client.msiType != msiTypeAppServiceV20170901 {
		t.Fatalf("Failed to detect the correct MSI Environment. Expected: %d, Received: %d", msiTypeAppServiceV20170901, msiCred.client.msiType)
	}
}

func TestManagedIdentityCredential_CreateAppServiceAuthRequestV20190801(t *testing.T) {
	t.Skip("App Service 2019-08-01 isn't supported because it's unavailable in some Functions apps.")
	// setting a dummy value for MSI_ENDPOINT in order to be able to get a ManagedIdentityCredential type in order
	// to test App Service authentication request creation.
	_ = os.Setenv("IDENTITY_ENDPOINT", "somevalue")
	_ = os.Setenv("IDENTITY_HEADER", "header")
	defer clearEnvVars("IDENTITY_ENDPOINT", "IDENTITY_HEADER")
	cred, err := NewManagedIdentityCredential(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	cred.client.endpoint = imdsEndpoint
	req, err := cred.client.createAuthRequest(context.Background(), ClientID(fakeClientID), []string{liveTestScope})
	if err != nil {
		t.Fatal(err)
	}
	if req.Raw().Header.Get("X-IDENTITY-HEADER") != "header" {
		t.Fatalf("Unexpected value for secret header")
	}
	reqQueryParams, err := url.ParseQuery(req.Raw().URL.RawQuery)
	if err != nil {
		t.Fatalf("Unable to parse App Service request query params: %v", err)
	}
	if reqQueryParams["api-version"][0] != "2019-08-01" {
		t.Fatalf("Unexpected App Service API version")
	}
	if reqQueryParams["resource"][0] != liveTestScope {
		t.Fatalf("Unexpected resource in resource query param")
	}
	if reqQueryParams[qpClientID][0] != fakeClientID {
		t.Fatalf("Unexpected client ID in resource query param")
	}
}

func TestManagedIdentityCredential_CreateAppServiceAuthRequestV20170901(t *testing.T) {
	// setting a dummy value for MSI_ENDPOINT in order to be able to get a ManagedIdentityCredential type in order
	// to test App Service authentication request creation.
	_ = os.Setenv("MSI_ENDPOINT", "somevalue")
	_ = os.Setenv("MSI_SECRET", "secret")
	defer clearEnvVars("MSI_ENDPOINT", "MSI_SECRET")
	cred, err := NewManagedIdentityCredential(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	cred.client.endpoint = imdsEndpoint
	req, err := cred.client.createAuthRequest(context.Background(), ClientID(fakeClientID), []string{liveTestScope})
	if err != nil {
		t.Fatal(err)
	}
	if req.Raw().Header.Get("secret") != "secret" {
		t.Fatalf("Unexpected value for secret header")
	}
	reqQueryParams, err := url.ParseQuery(req.Raw().URL.RawQuery)
	if err != nil {
		t.Fatalf("Unable to parse App Service request query params: %v", err)
	}
	if reqQueryParams["api-version"][0] != "2017-09-01" {
		t.Fatalf("Unexpected App Service API version")
	}
	if reqQueryParams["resource"][0] != liveTestScope {
		t.Fatalf("Unexpected resource in resource query param")
	}
	if reqQueryParams["clientid"][0] != fakeClientID {
		t.Fatalf("Unexpected client ID in resource query param")
	}
}

func TestManagedIdentityCredential_CreateAccessTokenExpiresOnStringInt(t *testing.T) {
	resetEnvironmentVarsForTest()
	srv, close := mock.NewServer()
	defer close()
	srv.AppendResponse(mock.WithBody([]byte(expiresOnIntResp)))
	_ = os.Setenv("MSI_ENDPOINT", srv.URL())
	_ = os.Setenv("MSI_SECRET", "secret")
	defer clearEnvVars("MSI_ENDPOINT", "MSI_SECRET")
	options := ManagedIdentityCredentialOptions{}
	options.Transport = srv
	msiCred, err := NewManagedIdentityCredential(&options)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	_, err = msiCred.GetToken(context.Background(), policy.TokenRequestOptions{Scopes: []string{liveTestScope}})
	if err != nil {
		t.Fatalf("Received an error when attempting to retrieve a token")
	}
}

func TestManagedIdentityCredential_GetTokenInAppServiceMockFail(t *testing.T) {
	resetEnvironmentVarsForTest()
	srv, close := mock.NewServer()
	defer close()
	srv.AppendResponse(mock.WithStatusCode(http.StatusUnauthorized))
	_ = os.Setenv("MSI_ENDPOINT", srv.URL())
	_ = os.Setenv("MSI_SECRET", "secret")
	defer clearEnvVars("MSI_ENDPOINT", "MSI_SECRET")
	options := ManagedIdentityCredentialOptions{}
	options.Transport = srv
	msiCred, err := NewManagedIdentityCredential(&options)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	_, err = msiCred.GetToken(context.Background(), policy.TokenRequestOptions{Scopes: []string{liveTestScope}})
	if err == nil {
		t.Fatalf("Expected an error but did not receive one")
	}
}

func TestManagedIdentityCredential_GetTokenIMDS400(t *testing.T) {
	resetEnvironmentVarsForTest()
	res := http.Response{StatusCode: http.StatusBadRequest, Body: io.NopCloser(bytes.NewBufferString(""))}
	options := ManagedIdentityCredentialOptions{}
	options.Transport = newMockImds(res, res, res)
	cred, err := NewManagedIdentityCredential(&options)
	if err != nil {
		t.Fatal(err)
	}
	// cred should return CredentialUnavailableError when IMDS responds 400 to a token request
	var expected CredentialUnavailableError
	for i := 0; i < 3; i++ {
		_, err = cred.GetToken(context.Background(), policy.TokenRequestOptions{Scopes: []string{liveTestScope}})
		if !errors.As(err, &expected) {
			t.Fatalf(`expected CredentialUnavailableError, got %T: "%s"`, err, err.Error())
		}
	}
}

func TestManagedIdentityCredential_NewManagedIdentityCredentialFail(t *testing.T) {
	resetEnvironmentVarsForTest()
	srv, close := mock.NewServer()
	defer close()
	srv.AppendResponse(mock.WithStatusCode(http.StatusUnauthorized))
	_ = os.Setenv("MSI_ENDPOINT", "https://t .com")
	defer clearEnvVars("MSI_ENDPOINT")
	options := ManagedIdentityCredentialOptions{}
	options.Transport = srv
	cred, err := NewManagedIdentityCredential(&options)
	if err != nil {
		t.Fatal(err)
	}
	_, err = cred.GetToken(context.Background(), policy.TokenRequestOptions{})
	if err == nil {
		t.Fatalf("Expected an error but did not receive one")
	}
}

func TestManagedIdentityCredential_GetTokenUnexpectedJSON(t *testing.T) {
	resetEnvironmentVarsForTest()
	srv, close := mock.NewServer()
	defer close()
	srv.AppendResponse(mock.WithBody([]byte(accessTokenRespMalformed)))
	_ = os.Setenv("MSI_ENDPOINT", srv.URL())
	defer clearEnvVars("MSI_ENDPOINT")
	options := ManagedIdentityCredentialOptions{}
	options.Transport = srv
	msiCred, err := NewManagedIdentityCredential(&options)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	_, err = msiCred.GetToken(context.Background(), policy.TokenRequestOptions{Scopes: []string{liveTestScope}})
	if err == nil {
		t.Fatalf("Expected a JSON marshal error but received nil")
	}
}

func TestManagedIdentityCredential_CreateIMDSAuthRequest(t *testing.T) {
	// setting a dummy value for MSI_ENDPOINT in order to be able to get a ManagedIdentityCredential type in order
	// to test IMDS authentication request creation.
	_ = os.Setenv("MSI_ENDPOINT", "somevalue")
	defer clearEnvVars("MSI_ENDPOINT")
	cred, err := NewManagedIdentityCredential(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	cred.client.endpoint = imdsEndpoint
	req, err := cred.client.createIMDSAuthRequest(context.Background(), ClientID(fakeClientID), []string{liveTestScope})
	if err != nil {
		t.Fatal(err)
	}
	if req.Raw().Header.Get(headerMetadata) != "true" {
		t.Fatalf("Unexpected value for Content-Type header")
	}
	reqQueryParams, err := url.ParseQuery(req.Raw().URL.RawQuery)
	if err != nil {
		t.Fatalf("Unable to parse IMDS query params: %v", err)
	}
	if reqQueryParams["api-version"][0] != imdsAPIVersion {
		t.Fatalf("Unexpected IMDS API version")
	}
	if reqQueryParams["resource"][0] != liveTestScope {
		t.Fatalf("Unexpected resource in resource query param")
	}
	if reqQueryParams["client_id"][0] != fakeClientID {
		t.Fatalf("Unexpected client ID. Expected: %s, Received: %s", fakeClientID, reqQueryParams["client_id"][0])
	}
	if u := req.Raw().URL.String(); !strings.HasPrefix(u, imdsEndpoint) {
		t.Fatalf("Unexpected default authority host %s", u)
	}
	if req.Raw().URL.Scheme != "http" {
		t.Fatalf("Wrong request scheme")
	}
}

func TestManagedIdentityCredential_GetTokenScopes(t *testing.T) {
	srv, close := mock.NewServer()
	defer close()
	srv.AppendResponse(mock.WithStatusCode(http.StatusUnauthorized))
	options := ManagedIdentityCredentialOptions{}
	options.Transport = srv
	msiCred, err := NewManagedIdentityCredential(&options)
	if err != nil {
		t.Fatal(err)
	}
	for _, scopes := range [][]string{nil, {}, {"a", "b"}} {
		_, err = msiCred.GetToken(context.Background(), policy.TokenRequestOptions{Scopes: scopes})
		if err == nil {
			t.Fatal("expected an error")
		}
		if !strings.Contains(err.Error(), "scope") {
			t.Fatalf(`unexpected error "%s"`, err.Error())
		}
	}
}

func TestManagedIdentityCredential_ScopesImmutable(t *testing.T) {
	resetEnvironmentVarsForTest()
	srv, close := mock.NewServer()
	defer close()
	srv.AppendResponse(mock.WithBody([]byte(expiresOnIntResp)))
	_ = os.Setenv(msiEndpoint, srv.URL())
	defer clearEnvVars(msiEndpoint)
	options := ManagedIdentityCredentialOptions{ClientOptions: azcore.ClientOptions{Transport: srv}}
	cred, err := NewManagedIdentityCredential(&options)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	scope := "https://localhost/.default"
	scopes := []string{scope}
	_, err = cred.GetToken(context.Background(), policy.TokenRequestOptions{Scopes: scopes})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if scopes[0] != scope {
		t.Fatalf("GetToken shouldn't mutate arguments")
	}
}

func TestManagedIdentityCredential_UseResourceID(t *testing.T) {
	resetEnvironmentVarsForTest()
	srv, close := mock.NewServer()
	defer close()
	srv.AppendResponse(mock.WithBody([]byte(appServiceWindowsSuccessResp)))
	_ = os.Setenv("MSI_ENDPOINT", srv.URL())
	_ = os.Setenv("MSI_SECRET", "secret")
	defer clearEnvVars("MSI_ENDPOINT", "MSI_SECRET")
	options := ManagedIdentityCredentialOptions{}
	options.Transport = srv
	options.ID = ResourceID("sample/resource/id")
	cred, err := NewManagedIdentityCredential(&options)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	tk, err := cred.GetToken(context.Background(), policy.TokenRequestOptions{Scopes: []string{liveTestScope}})
	if err != nil {
		t.Fatal(err)
	}
	if tk.Token != "new_token" {
		t.Fatalf("unexpected token returned. Expected: %s, Received: %s", "new_token", tk.Token)
	}
}

func TestManagedIdentityCredential_ResourceID_AppServiceV20190801(t *testing.T) {
	t.Skip("App Service 2019-08-01 isn't supported because it's unavailable in some Functions apps.")
	_ = os.Setenv("IDENTITY_ENDPOINT", "somevalue")
	_ = os.Setenv("IDENTITY_HEADER", "header")
	defer clearEnvVars("IDENTITY_ENDPOINT", "IDENTITY_HEADER")
	resID := "sample/resource/id"
	cred, err := NewManagedIdentityCredential(&ManagedIdentityCredentialOptions{ID: ResourceID(resID)})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	cred.client.endpoint = imdsEndpoint
	req, err := cred.client.createAuthRequest(context.Background(), cred.id, []string{liveTestScope})
	if err != nil {
		t.Fatal(err)
	}
	if req.Raw().Header.Get("X-IDENTITY-HEADER") != "header" {
		t.Fatalf("Unexpected value for secret header")
	}
	reqQueryParams, err := url.ParseQuery(req.Raw().URL.RawQuery)
	if err != nil {
		t.Fatalf("Unable to parse App Service request query params: %v", err)
	}
	if reqQueryParams["api-version"][0] != "2019-08-01" {
		t.Fatalf("Unexpected App Service API version")
	}
	if reqQueryParams["resource"][0] != liveTestScope {
		t.Fatalf("Unexpected resource in resource query param")
	}
	if reqQueryParams[qpResID][0] != resID {
		t.Fatalf("Unexpected resource ID in resource query param")
	}
}

func TestManagedIdentityCredential_ResourceID_IMDS(t *testing.T) {
	_ = os.Setenv("MSI_ENDPOINT", "http://localhost/")
	defer clearEnvVars("MSI_ENDPOINT")
	resID := "sample/resource/id"
	cred, err := NewManagedIdentityCredential(&ManagedIdentityCredentialOptions{ID: ResourceID(resID)})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	cred.client.msiType = msiTypeIMDS
	cred.client.endpoint = imdsEndpoint
	req, err := cred.client.createAuthRequest(context.Background(), cred.id, []string{liveTestScope})
	if err != nil {
		t.Fatal(err)
	}
	reqQueryParams, err := url.ParseQuery(req.Raw().URL.RawQuery)
	if err != nil {
		t.Fatalf("Unable to parse App Service request query params: %v", err)
	}
	if reqQueryParams["api-version"][0] != "2018-02-01" {
		t.Fatalf("Unexpected App Service API version")
	}
	if reqQueryParams["resource"][0] != liveTestScope {
		t.Fatalf("Unexpected resource in resource query param")
	}
	if reqQueryParams[qpResID][0] != resID {
		t.Fatalf("Unexpected resource ID in resource query param")
	}
}

func TestManagedIdentityCredential_CreateAccessTokenExpiresOnInt(t *testing.T) {
	resetEnvironmentVarsForTest()
	srv, close := mock.NewServer()
	defer close()
	srv.AppendResponse(mock.WithBody([]byte(expiresOnNonStringIntResp)))
	_ = os.Setenv("MSI_ENDPOINT", srv.URL())
	_ = os.Setenv("MSI_SECRET", "secret")
	defer clearEnvVars("MSI_ENDPOINT", "MSI_SECRET")
	options := ManagedIdentityCredentialOptions{}
	options.Transport = srv
	msiCred, err := NewManagedIdentityCredential(&options)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	_, err = msiCred.GetToken(context.Background(), policy.TokenRequestOptions{Scopes: []string{liveTestScope}})
	if err != nil {
		t.Fatalf("Received an error when attempting to retrieve a token")
	}
}

// adding an incorrect string value in expires_on
func TestManagedIdentityCredential_CreateAccessTokenExpiresOnFail(t *testing.T) {
	resetEnvironmentVarsForTest()
	srv, close := mock.NewServer()
	defer close()
	srv.AppendResponse(mock.WithBody([]byte(`{"access_token": "new_token", "refresh_token": "", "expires_in": "", "expires_on": "15609740s28", "not_before": "1560970130", "resource": "https://vault.azure.net", "token_type": "Bearer"}`)))
	_ = os.Setenv("MSI_ENDPOINT", srv.URL())
	_ = os.Setenv("MSI_SECRET", "secret")
	defer clearEnvVars("MSI_ENDPOINT", "MSI_SECRET")
	options := ManagedIdentityCredentialOptions{}
	options.Transport = srv
	msiCred, err := NewManagedIdentityCredential(&options)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	_, err = msiCred.GetToken(context.Background(), policy.TokenRequestOptions{Scopes: []string{liveTestScope}})
	if err == nil {
		t.Fatalf("expected to receive an error but received none")
	}
}

func TestManagedIdentityCredential_IMDSLive(t *testing.T) {
	switch recording.GetRecordMode() {
	case recording.LiveMode:
		t.Skip("this test doesn't run in live mode because it can't pass in CI")
	case recording.RecordingMode:
		// record iff either managed identity environment variable is set, because
		// otherwise there's no reason to believe the test is running on a VM
		if len(liveManagedIdentity.clientID)+len(liveManagedIdentity.resourceID) == 0 {
			t.Skip("neither MANAGED_IDENTITY_CLIENT_ID nor MANAGED_IDENTITY_RESOURCE_ID is set")
		}
	}
	opts, stop := initRecording(t)
	defer stop()
	cred, err := NewManagedIdentityCredential(&ManagedIdentityCredentialOptions{ClientOptions: opts})
	if err != nil {
		t.Fatal(err)
	}
	tk, err := cred.GetToken(context.Background(), policy.TokenRequestOptions{Scopes: []string{liveTestScope}})
	if err != nil {
		t.Fatal(err)
	}
	if tk.Token == "" {
		t.Fatal("GetToken returned an invalid token")
	}
	if tk.ExpiresOn.Before(time.Now().UTC()) {
		t.Fatal("GetToken returned an invalid expiration time")
	}
}

func TestManagedIdentityCredential_IMDSClientIDLive(t *testing.T) {
	switch recording.GetRecordMode() {
	case recording.LiveMode:
		t.Skip("this test doesn't run in live mode because it can't pass in CI")
	case recording.RecordingMode:
		if liveManagedIdentity.clientID == "" {
			t.Skip("MANAGED_IDENTITY_CLIENT_ID isn't set")
		}
	}
	opts, stop := initRecording(t)
	defer stop()
	o := ManagedIdentityCredentialOptions{ClientOptions: opts, ID: ClientID(liveManagedIdentity.clientID)}
	cred, err := NewManagedIdentityCredential(&o)
	if err != nil {
		t.Fatal(err)
	}
	tk, err := cred.GetToken(context.Background(), policy.TokenRequestOptions{Scopes: []string{liveTestScope}})
	if err != nil {
		t.Fatal(err)
	}
	if tk.Token == "" {
		t.Fatal("GetToken returned an invalid token")
	}
	if tk.ExpiresOn.Before(time.Now().UTC()) {
		t.Fatal("GetToken returned an invalid expiration time")
	}
}

func TestManagedIdentityCredential_IMDSResourceIDLive(t *testing.T) {
	switch recording.GetRecordMode() {
	case recording.LiveMode:
		t.Skip("this test doesn't run in live mode because it can't pass in CI")
	case recording.RecordingMode:
		if liveManagedIdentity.resourceID == "" {
			t.Skip("MANAGED_IDENTITY_RESOURCE_ID isn't set")
		}
	}
	opts, stop := initRecording(t)
	defer stop()
	o := ManagedIdentityCredentialOptions{ClientOptions: opts, ID: ResourceID(liveManagedIdentity.resourceID)}
	cred, err := NewManagedIdentityCredential(&o)
	if err != nil {
		t.Fatal(err)
	}
	tk, err := cred.GetToken(context.Background(), policy.TokenRequestOptions{Scopes: []string{liveTestScope}})
	if err != nil {
		t.Fatal(err)
	}
	if tk.Token == "" {
		t.Fatal("GetToken returned an invalid token")
	}
	if tk.ExpiresOn.Before(time.Now().UTC()) {
		t.Fatal("GetToken returned an invalid expiration time")
	}
}

func TestManagedIdentityCredential_IMDSTimeoutExceeded(t *testing.T) {
	resetEnvironmentVarsForTest()
	cred, err := NewManagedIdentityCredential(&ManagedIdentityCredentialOptions{
		ClientOptions: policy.ClientOptions{
			PerCallPolicies: []policy.Policy{delayPolicy{delay: time.Microsecond}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	cred.client.imdsTimeout = time.Nanosecond
	tk, err := cred.GetToken(context.Background(), policy.TokenRequestOptions{Scopes: []string{liveTestScope}})
	var expected CredentialUnavailableError
	if !errors.As(err, &expected) {
		t.Fatalf(`expected CredentialUnavailableError, got %T: "%v"`, err, err)
	}
	if tk != nil {
		t.Fatal("GetToken returned a token and an error")
	}
}

func TestManagedIdentityCredential_IMDSTimeoutSuccess(t *testing.T) {
	resetEnvironmentVarsForTest()
	res := http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewBufferString(accessTokenRespSuccess))}
	options := ManagedIdentityCredentialOptions{}
	options.Transport = newMockImds(res, res)
	cred, err := NewManagedIdentityCredential(&options)
	if err != nil {
		t.Fatal(err)
	}
	cred.client.imdsTimeout = time.Minute
	tk, err := cred.GetToken(context.Background(), policy.TokenRequestOptions{Scopes: []string{liveTestScope}})
	if err != nil {
		t.Fatal(err)
	}
	if tk.Token != tokenValue {
		t.Fatalf(`got unexpected token "%s"`, tk.Token)
	}
	if !tk.ExpiresOn.After(time.Now().UTC()) {
		t.Fatal("GetToken returned an invalid expiration time")
	}
	if cred.client.imdsTimeout > 0 {
		t.Fatal("credential didn't remove IMDS timeout after receiving a response")
	}
}
