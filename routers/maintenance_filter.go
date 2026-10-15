// Copyright 2026 The StuHelper Authors. Licensed under the Apache License, Version 2.0.
package routers

import (
	"net/http"

	"github.com/beego/beego/v2/server/web/context"
	"github.com/casdoor/casdoor/maintenance"
)

func MaintenanceFilter(ctx *context.Context) {
	applyMaintenanceFilter(ctx, maintenance.Default.Active())
}

func applyMaintenanceFilter(ctx *context.Context, active bool) {
	if !active {
		return
	}
	path := ctx.Request.URL.Path
	if (ctx.Request.Method == http.MethodGet || ctx.Request.Method == http.MethodHead) &&
		(path == "/.well-known/openid-configuration" || path == "/.well-known/jwks") {
		return
	}
	ctx.Output.Header("Cache-Control", "no-store")
	ctx.Output.Header("Retry-After", "60")
	ctx.Output.Header("X-StuHelper-Maintenance", "sso-migration")
	ctx.Output.SetStatus(http.StatusServiceUnavailable)
	_ = ctx.Output.Body([]byte("Identity service maintenance is in progress. Please retry shortly.\n"))
}
