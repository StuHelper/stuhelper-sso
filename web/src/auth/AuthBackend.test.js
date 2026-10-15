/* eslint-env jest */

// Copyright 2026 The Casdoor Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

jest.mock("./Auth", () => ({authConfig: {serverUrl: ""}}));
jest.mock("../Setting", () => ({getAcceptLanguage: () => "en"}));

const {
  completeDeviceLogin,
  getApplicationLogin,
  login,
  oAuthParamsToQuery,
  signup,
  updateRequiredUsername,
} = require("./AuthBackend");
const {grantConsent} = require("../backend/ConsentBackend");

test("keeps the RP nonce and StuHelper authorization binding independent", () => {
  const state = " rp state &=+ /~._- kept byte-for-byte ";
  const nonce = " rp nonce &=+ /~._- kept byte-for-byte ";
  const query = new URLSearchParams(oAuthParamsToQuery({
    clientId: "op_dynamic-client",
    responseType: "code",
    redirectUri: "https://app.example.com/callback",
    type: "code",
    scope: "openid profile",
    state,
    nonce,
    stuHelperAuthz: "ag1:7:opaque:mac",
    challengeMethod: "S256",
    codeChallenge: "challenge-value",
  }));

  expect(query.get("state")).toBe(state);
  expect(query.get("nonce")).toBe(nonce);
  expect(query.get("stuhelper_authz")).toBe("ag1:7:opaque:mac");
});

test("preserves opaque OIDC fields on every binding-bearing login API path", async() => {
  const originalFetch = global.fetch;
  global.fetch = jest.fn().mockResolvedValue({json: () => Promise.resolve({status: "ok"})});
  const state = " rp state &=+ /~._- kept byte-for-byte ";
  const nonce = " rp nonce &=+ /~._- kept byte-for-byte ";
  const params = {
    clientId: "op_dynamic-client",
    responseType: "code",
    redirectUri: "https://app.example.com/callback",
    type: "code",
    scope: "openid profile",
    state,
    nonce,
    stuHelperAuthz: "ag1:7:opaque:mac",
    challengeMethod: "S256",
    codeChallenge: "challenge-value",
  };

  try {
    await getApplicationLogin(params);
    await login({}, params);
    await signup({}, params);
    await completeDeviceLogin("device-code", params);

    const expectedPaths = [
      "/api/get-app-login",
      "/api/login",
      "/api/signup",
      "/api/device-auth-complete",
    ];
    expect(global.fetch).toHaveBeenCalledTimes(expectedPaths.length);
    global.fetch.mock.calls.forEach(([rawUrl], index) => {
      const parsed = new URL(rawUrl, "https://sso.example.com");
      expect(parsed.pathname).toBe(expectedPaths[index]);
      expect(parsed.searchParams.get("state")).toBe(state);
      expect(parsed.searchParams.get("nonce")).toBe(nonce);
      expect(parsed.searchParams.get("stuhelper_authz")).toBe("ag1:7:opaque:mac");
    });
  } finally {
    global.fetch = originalFetch;
  }
});

test("consent grant forwards nonce and binding as distinct fields", async() => {
  const originalFetch = global.fetch;
  global.fetch = jest.fn().mockResolvedValue({json: () => Promise.resolve({status: "ok"})});

  try {
    await grantConsent({application: "admin/app", grantedScopes: ["profile"]}, {
      clientId: "op_dynamic-client",
      responseType: "code",
      redirectUri: "https://app.example.com/callback",
      scope: "openid profile",
      state: "state-value",
      nonce: "rp-client-nonce-kept-exactly",
      stuHelperAuthz: "ag1:7:opaque:mac",
      codeChallenge: "challenge-value",
    });
    const request = global.fetch.mock.calls[0][1];
    const body = JSON.parse(request.body);
    expect(body.nonce).toBe("rp-client-nonce-kept-exactly");
    expect(body.stuHelperAuthz).toBe("ag1:7:opaque:mac");
  } finally {
    global.fetch = originalFetch;
  }
});

test("forwards OIDC reauthentication parameters to the login API", () => {
  const query = new URLSearchParams(oAuthParamsToQuery({
    clientId: "client-id",
    responseType: "code",
    redirectUri: "https://app.example.com/callback",
    type: "code",
    scope: "openid profile",
    state: "state-value",
    nonce: "nonce-value",
    challengeMethod: "S256",
    codeChallenge: "challenge-value",
    prompt: "login",
    maxAge: "0",
    acrValues: "mfa",
  }));

  expect(query.get("prompt")).toBe("login");
  expect(query.get("maxAge")).toBe("0");
  expect(query.get("acrValues")).toBe("mfa");
});

test("does not add reauthentication parameters to ordinary login requests", () => {
  const query = new URLSearchParams(oAuthParamsToQuery({
    clientId: "client-id",
    responseType: "code",
    redirectUri: "https://app.example.com/callback",
    type: "code",
    scope: "openid profile",
    state: "state-value",
    nonce: "nonce-value",
    challengeMethod: "S256",
    codeChallenge: "challenge-value",
  }));

  expect(query.has("prompt")).toBe(false);
  expect(query.has("maxAge")).toBe(false);
  expect(query.has("acrValues")).toBe(false);
});

test("submits the one-time username repair through the dedicated endpoint", async() => {
  const originalFetch = global.fetch;
  global.fetch = jest.fn().mockResolvedValue({json: () => Promise.resolve({status: "ok"})});

  try {
    await updateRequiredUsername("admin", "stuhelper-web", "ValidUser1");
    expect(global.fetch).toHaveBeenCalledWith("/api/update-required-username", expect.objectContaining({
      method: "POST",
      credentials: "include",
      body: JSON.stringify({
        applicationOwner: "admin",
        applicationName: "stuhelper-web",
        username: "ValidUser1",
      }),
    }));
  } finally {
    global.fetch = originalFetch;
  }
});
