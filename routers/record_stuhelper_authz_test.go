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

package routers

import (
	"net/http/httptest"
	"strings"
	"testing"

	beegocontext "github.com/beego/beego/v2/server/web/context"
)

func TestAfterRecordMessageConstructorRedactsStuHelperAuthorizationBinding(t *testing.T) {
	const canary = "STUHELPER_AFTER_RECORD_AUTHZ_CANARY"
	body := `{"username":"ordinary-user","stuHelperAuthz":"` + canary + `"}`
	request := httptest.NewRequest("POST", "/api/signup?flow=ordinary&stuhelper_authz="+canary, strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	ctx := beegocontext.NewContext()
	ctx.Reset(httptest.NewRecorder(), request)
	ctx.Input.RequestBody = []byte(body)

	record, err := newRecordForAfterRecordMessage(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(record.RequestUri, canary) || strings.Contains(record.Object, canary) {
		t.Fatalf("AfterRecordMessage constructor retained authorization binding: %#v", record)
	}
	if !strings.Contains(record.RequestUri, "flow=ordinary") || !strings.Contains(record.Object, `"username":"ordinary-user"`) {
		t.Fatalf("AfterRecordMessage constructor lost ordinary audit context: %#v", record)
	}
}
