/*
 * Copyright 2017 Sean Klein
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this software and
 * associated documentation files (the "Software"), to deal in the Software without restriction,
 * including without limitation the rights to use, copy, modify, merge, publish, distribute,
 * sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all copies or
 * substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT
 * NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
 * DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#pragma once

#include <WString.h>
#include <WiFiClientSecure.h>

#define GACCOUNT_HOST "accounts.google.com"
#define GACCOUNT_SSL_PORT 443

#define GAPI_HOST "www.googleapis.com"
#define GAPI_SSL_PORT 443

class GoogleAuthenticator {
public:
  // Refer to https://developers.google.com/identity/protocols/OAuth2ForDevices
  // for more details on the authorization process.
  GoogleAuthenticator(const String ClientID, const String ClientSecret) :
    ClientID_(ClientID), ClientSecret_(ClientSecret) {}

  // Begins authorization process for a client to access
  // a particular scope.
  //
  // - Scope: Describes subcomponent of Google API which
  // will be accessed. For a full list, refer to:
  // https://developers.google.com/identity/protocols/googlescopes
  //
  // On success, returns 0.
  // Additionally, "DeviceCode" and "UserCode" will become
  // available after this function returns success.
  int QueryUserCode(WiFiClientSecure& client, const String& Scope);

  // AFTER the user has manually inputted the "UserCode" at the verification
  // URL from "QueryUserCode", this function may return "0" if it succesfully
  // sets the AccessToken.
  int QueryAccessToken(WiFiClientSecure& client);

  const String DeviceCode() const { return String(oauthDeviceCode); }
  const String UserCode() const { return String(oauthUserCode); }
  const String AccessToken() const { return String(accessToken); }

private:
  const String ClientID_;
  const String ClientSecret_;

  // Value uniquely assigned to the current device
  char oauthDeviceCode[1024]{};
  // Case-sensitive value that must be inputted
  // manually from a user on a trusted device
  char oauthUserCode[128]{};
  // Token which, upon success, may be used to
  // access authorized APIs
  char accessToken[1024]{};
};

// TODO(smklein): Maybe move somewhere else...
String sendPostCommand(WiFiClientSecure& client,
                       const String& host, int port,
                       const String& endpoint, const String& command);

