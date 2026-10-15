package routers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	beegocontext "github.com/beego/beego/v2/server/web/context"
)

func TestMaintenanceBlocksEveryIdentityEntryExceptReadOnlyDiscovery(t *testing.T) {
	for _, path := range []string{"/api/login", "/api/signup", "/api/login/oauth/access_token", "/api/acs",
		"/api/get-user", "/login/oauth/authorize", "/api/forward-auth", "/.well-known/jwks/extra", "/"} {
		for _, method := range []string{http.MethodGet, http.MethodPost, http.MethodOptions} {
			response := httptest.NewRecorder()
			ctx := beegocontext.NewContext()
			ctx.Reset(response, httptest.NewRequest(method, path, nil))
			applyMaintenanceFilter(ctx, true)
			if response.Code != http.StatusServiceUnavailable || response.Header().Get("X-StuHelper-Maintenance") != "sso-migration" {
				t.Fatalf("maintenance allowed %s %s", method, path)
			}
		}
	}
	for _, path := range []string{"/.well-known/openid-configuration", "/.well-known/jwks"} {
		for _, method := range []string{http.MethodGet, http.MethodHead, http.MethodPost} {
			response := httptest.NewRecorder()
			ctx := beegocontext.NewContext()
			ctx.Reset(response, httptest.NewRequest(method, path, nil))
			applyMaintenanceFilter(ctx, true)
			if (method == http.MethodPost) != (response.Code == http.StatusServiceUnavailable) {
				t.Fatalf("unexpected discovery maintenance policy for %s %s", method, path)
			}
		}
	}
}
