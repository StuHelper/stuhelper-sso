// StuHelper's request binding is opaque. Keep it separate from the RP's nonce,
// and encode every value exactly once at the HTTP boundary.
export function oauthParamsToQuery(params: Record<string, unknown> | null | undefined): string {
  if (!params) {
    return "";
  }
  const query = new URLSearchParams();
  const fields: Record<string, string> = {
    clientId: "clientId", responseType: "responseType", redirectUri: "redirectUri",
    type: "type", scope: "scope", state: "state", nonce: "nonce",
    challengeMethod: "code_challenge_method", codeChallenge: "code_challenge",
    resource: "resource", stuHelperAuthz: "stuhelper_authz", prompt: "prompt",
    maxAge: "max_age", acrValues: "acrValues",
  };
  for (const [field, key] of Object.entries(fields)) {
    const value = params[field];
    if (value !== undefined && value !== null && value !== "") {
      query.set(key, String(value));
    }
  }
  return `?${query.toString()}`;
}

export const stuHelperUsernameRegex = "^[A-Za-z][A-Za-z0-9]{4,19}$";

export function isRequiredAccountItemAnswered(user: {name?: string; phone?: string} | null, item: {name: string; regex?: string}): boolean | undefined {
  if (!user) {
    return false;
  }
  if (item.name === "Phone") {
    return typeof user.phone === "string" && user.phone.trim() !== "";
  }
  if (item.name === "Username") {
    if (typeof user.name !== "string" || user.name.trim() === "") {
      return false;
    }
    try {
      return !item.regex || new RegExp(item.regex).test(user.name);
    } catch {
      return false;
    }
  }
  return undefined;
}

export function requiredSetupSigninUrl(signinUrl: string | null, origin: string): string {
  if (!signinUrl) {
    return "";
  }
  try {
    const url = new URL(signinUrl, origin);
    if (url.origin !== origin) {
      return "";
    }
    url.searchParams.set("silentSignin", "1");
    return `${url.pathname}${url.search}${url.hash}`;
  } catch {
    return "";
  }
}

export function beginOAuthRedirectOnce(owner: {oauthCallbackRedirectStarted: boolean}): boolean {
  if (owner.oauthCallbackRedirectStarted) {
    return false;
  }
  owner.oauthCallbackRedirectStarted = true;
  return true;
}
