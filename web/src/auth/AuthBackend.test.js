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

const {oAuthParamsToQuery, updateRequiredUsername} = require("./AuthBackend");

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
