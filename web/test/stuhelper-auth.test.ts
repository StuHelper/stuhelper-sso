import assert from "node:assert/strict";
import {test} from "node:test";
import {createRequire} from "node:module";
import vm from "node:vm";
import {build} from "esbuild";
import {beginOAuthRedirectOnce, isRequiredAccountItemAnswered, oauthParamsToQuery, requiredSetupSigninUrl, stuHelperUsernameRegex} from "../src/auth/stuhelper.ts";

const request = {
  clientId: "app &client", responseType: "code", type: "code",
  redirectUri: "https://rp.example/callback?existing=1", scope: "openid profile offline_access",
  state: "  state +&=/%? 中文  ", nonce: "  nonce +&=/%? 中文  ",
  stuHelperAuthz: "ag1:7:opaque+&=/envelope:mac", codeChallenge: "pkce+/=", challengeMethod: "S256",
  prompt: "login", maxAge: 0, acrValues: "mfa", resource: "https://api.example/resource?x=1",
};

test("OAuth request values survive URL encoding, including numeric max_age=0", () => {
  const query = new URLSearchParams(oauthParamsToQuery(request));
  assert.equal(query.get("nonce"), request.nonce);
  assert.equal(query.get("state"), request.state);
  assert.equal(query.get("stuhelper_authz"), request.stuHelperAuthz);
  assert.equal(query.get("max_age"), "0");
  assert.equal(query.get("acrValues"), "mfa");
  assert.equal(query.get("code_challenge"), request.codeChallenge);
  assert.equal(query.get("redirectUri"), request.redirectUri);
  assert.equal(query.get("scope"), request.scope);
  assert.equal(oauthParamsToQuery(null), "");
  assert.equal(oauthParamsToQuery(undefined), "");
});

async function loadBackend(name: string, calls: Array<{url: string; options: RequestInit}>) {
  const output = await build({
    entryPoints: [`src/backend/${name}.ts`], bundle: true, write: false, platform: "node", format: "cjs",
    plugins: [{name: "test-runtime", setup(builder) {
      builder.onResolve({filter: /^@\/(lib\/setting|auth\/Auth)$/}, (args) => ({path: args.path, namespace: "test-runtime"}));
      builder.onLoad({filter: /.*/, namespace: "test-runtime"}, () => ({contents: 'export const ServerUrl = "https://sso.example"; export const authConfig = {serverUrl: ServerUrl}; export const getAcceptLanguage = () => "en";', loader: "js"}));
    }}],
  });
  const module = {exports: {} as Record<string, (...args: any[]) => Promise<any>>};
  vm.runInNewContext(output.outputFiles[0].text, {
    module, exports: module.exports, require: createRequire(import.meta.url), URLSearchParams,
    fetch: async (url: string, options: RequestInit) => {
      calls.push({url, options});
      return {json: async () => ({status: "ok"})};
    },
  });
  return module.exports;
}

test("the live v4 login, signup, application and device APIs carry nonce and binding independently", async () => {
  const calls: Array<{url: string; options: RequestInit}> = [];
  const backend = await loadBackend("AuthBackend", calls);
  await backend.login({username: "synthetic"}, request);
  await backend.signup({username: "synthetic"}, request);
  await backend.getApplicationLogin(request);
  await backend.completeDeviceLogin("device-code", request);
  for (const call of calls) {
    const query = new URL(call.url).searchParams;
    assert.equal(query.get("nonce"), request.nonce);
    assert.equal(query.get("stuhelper_authz"), request.stuHelperAuthz);
    assert.equal(query.get("state"), request.state);
    assert.equal(query.get("max_age"), "0");
    assert.equal(call.options.credentials, "include");
  }
});

test("consent sends the opaque binding as its own JSON field", async () => {
  const calls: Array<{url: string; options: RequestInit}> = [];
  const backend = await loadBackend("ConsentBackend", calls);
  await backend.grantConsent({consent: true}, request);
  const body = JSON.parse(String(calls[0].options.body));
  assert.equal(body.nonce, request.nonce);
  assert.equal(body.stuHelperAuthz, request.stuHelperAuthz);
  assert.equal(body.responseType, "code");
});

test("username correction uses the dedicated endpoint and only its required fields", async () => {
  const calls: Array<{url: string; options: RequestInit}> = [];
  const backend = await loadBackend("AuthBackend", calls);
  await backend.updateRequiredUsername("admin", "stuhelper", "Alice123");
  assert.equal(new URL(calls[0].url).pathname, "/api/update-required-username");
  assert.deepEqual(JSON.parse(String(calls[0].options.body)), {applicationOwner: "admin", applicationName: "stuhelper", username: "Alice123"});
});

test("required account items reject missing phones, invalid names and invalid policy regexes", () => {
  const username = {name: "Username", regex: stuHelperUsernameRegex};
  assert.equal(isRequiredAccountItemAnswered({name: "Alice123"}, username), true);
  for (const name of ["", " ", "a", "12345", "alice_name"]) {
    assert.equal(isRequiredAccountItemAnswered({name}, username), false);
  }
  assert.equal(isRequiredAccountItemAnswered({name: "Alice123"}, {...username, regex: "["}), false);
  assert.equal(isRequiredAccountItemAnswered({phone: " "}, {name: "Phone"}), false);
  assert.equal(isRequiredAccountItemAnswered({phone: "synthetic-verified-phone"}, {name: "Phone"}), true);
  assert.equal(isRequiredAccountItemAnswered(null, username), false);
  assert.equal(isRequiredAccountItemAnswered({}, {name: "Country/Region"}), undefined);
});

test("account setup resumes the original local request without an external redirect", () => {
  const original = `/login/oauth/authorize?${new URLSearchParams({nonce: request.nonce, stuhelper_authz: request.stuHelperAuthz, prompt: "login", max_age: "0"})}`;
  const next = new URL(requiredSetupSigninUrl(original, "https://sso.example"), "https://sso.example");
  assert.equal(next.searchParams.get("nonce"), request.nonce);
  assert.equal(next.searchParams.get("stuhelper_authz"), request.stuHelperAuthz);
  assert.equal(next.searchParams.get("silentSignin"), "1");
  assert.equal(requiredSetupSigninUrl("https://other.example/", "https://sso.example"), "");
  assert.equal(requiredSetupSigninUrl(null, "https://sso.example"), "");
});

test("concurrent completion handlers can initiate only one code redirect", () => {
  const state = {oauthCallbackRedirectStarted: false};
  assert.equal(beginOAuthRedirectOnce(state), true);
  assert.equal(beginOAuthRedirectOnce(state), false);
  assert.equal(beginOAuthRedirectOnce(state), false);
});
