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

import React from "react";
import {Alert, Button, Input} from "antd";

jest.mock("react-router-dom", () => ({withRouter: component => component}));
jest.mock("i18next", () => ({t: key => key}));
jest.mock("antd", () => ({
  Alert: "Alert",
  Button: "Button",
  Card: "Card",
  Col: "Col",
  Input: "Input",
  Result: "Result",
  Row: "Row",
}));
jest.mock("../common/select/AffiliationSelect", () => () => null);
jest.mock("../common/OAuthWidget", () => () => null);
jest.mock("../common/select/RegionSelect", () => () => null);
jest.mock("../common/modal/ResetModal", () => () => null);
jest.mock("../Setting", () => ({
  hasPromptPage: () => true,
  isAffiliationPrompted: () => false,
  isProviderPrompted: () => false,
  isSignupItemPrompted: item => item.prompted === true,
  isSignupItemAnswered: (user, item) => item.name !== "Username" || /^[A-Za-z][A-Za-z0-9]{4,19}$/.test(user.name),
  isPromptAnswered: () => false,
}));

const PromptPage = require("./PromptPage").default;

function findElement(node, predicate) {
  if (Array.isArray(node)) {
    for (const child of node) {
      const match = findElement(child, predicate);
      if (match) {
        return match;
      }
    }
    return null;
  }
  if (!React.isValidElement(node)) {
    return null;
  }
  if (predicate(node)) {
    return node;
  }
  return findElement(React.Children.toArray(node.props.children), predicate);
}

test("keeps the one-time username repair input editable", () => {
  const application = {
    providers: [],
    signupItems: [{
      name: "Username",
      prompted: true,
      regex: "^[A-Za-z][A-Za-z0-9]{4,19}$",
    }],
  };
  const page = new PromptPage({
    account: {name: "legacy_name", owner: "stuhelper"},
    application,
    applicationName: "stuhelper-web",
  });
  page.state.user = {name: "legacy_name"};
  page.setState = update => {
    const next = typeof update === "function" ? update(page.state, page.props) : update;
    page.state = {...page.state, ...next};
  };

  page.initSteps(page.state.user, application);
  expect(typeof page.state.steps[0].content).toBe("function");

  let content = page.state.steps[0].content();
  let input = findElement(content, element => element.type === Input);
  let updateButton = findElement(content, element => element.type === Button && element.props.block === true);
  let alert = findElement(content, element => element.type === Alert);
  expect(input.props.value).toBe("");
  expect(updateButton.props.disabled).toBe(true);
  expect(alert.props.description).toBe("application:Username must follow the StuHelper rule and can be changed once");

  input.props.onChange({target: {value: "ValidUser1"}});

  content = page.state.steps[0].content();
  input = findElement(content, element => element.type === Input);
  updateButton = findElement(content, element => element.type === Button && element.props.block === true);
  expect(input.props.value).toBe("ValidUser1");
  expect(updateButton.props.disabled).toBe(false);

  application.signupItems[0].regex = "^[a-z]{3,30}$";
  content = page.state.steps[0].content();
  alert = findElement(content, element => element.type === Alert);
  expect(alert.props.description).toBe("application:Username can be changed once and is immutable afterwards");
});
