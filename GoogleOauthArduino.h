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

#include <EEPROM.h>
#include <WString.h>
#include <WiFiClientSecure.h>

#define GACCOUNT_HOST "accounts.google.com"
#define GACCOUNT_SSL_PORT 443

#define GAPI_HOST "www.googleapis.com"
#define GAPI_SSL_PORT 443

// Forward declaration so it can manipulate the
// internals of the Authentication Request.
class GoogleAuthenticator;

class GoogleAuthRequest {
  friend class GoogleAuthenticator;
public:
  const String DeviceCode() const { return String(oauthDeviceCode); }
  const String UserCode() const { return String(oauthUserCode); }
  const char* UserCodeCStr() const { return oauthUserCode; }
  const String VerifyURL() const { return String(verifyURL); }
  const char* VerifyURLCStr() const { return verifyURL; }

private:
  // Value uniquely assigned to the current device
  char oauthDeviceCode[1024];
  // Case-sensitive value that must be inputted
  // manually from a user on a trusted device
  char oauthUserCode[128];

  // URL at which the user must input the UserCode
  char verifyURL[1024];

  // Time at which the authentication request will
  // become invalid.
  // May be compared directly with "millis".
  unsigned long expirationMs;

  // Don't bother issuing a request until this time passes.
  // May be compared directly with "millis".
  unsigned long nextMs;

  // How long to wait before next query (ms)
  unsigned long intervalMs;
};

class GoogleAuthenticator {
public:
  // Refer to https://developers.google.com/identity/protocols/OAuth2ForDevices
  // for more details on the authorization process.
  GoogleAuthenticator(const String ClientID, const String ClientSecret) :
    ClientID_(ClientID), ClientSecret_(ClientSecret) {}

  // Begins authorization process for a client to access
  // a particular scope.
  //
  // Scope: Describes subcomponent of Google API which
  // will be accessed. For a full list, refer to:
  // https://developers.google.com/identity/protocols/googlescopes
  //
  // On success, returns 0.
  int QueryUserCode(WiFiClientSecure& client, const String& Scope,
                    GoogleAuthRequest* out);

  // AFTER the user has manually inputted the "UserCode" at the verification
  // URL from "QueryUserCode", this function may return "0" if it succesfully
  // sets the AccessToken.
  //
  // If the authRequest is not ready to be queried, no request is sent,
  // and -1 is returned.
  int QueryAccessToken(WiFiClientSecure& client, GoogleAuthRequest* authRequest);

  // If the access token has expired, acquire another
  // one using the provided refresh token.
  int QueryRefresh(WiFiClientSecure& client);

  int EEPROMLength() { return sizeof(refreshToken); }
  int EEPROMStore(int addr) {
    EEPROM.begin(512);
    EEPROM.put(addr, refreshToken);
    EEPROM.end();
    return 0;
  }
  int EEPROMAcquire(int addr) {
    EEPROM.begin(512);
    EEPROM.get(addr, refreshToken);
    EEPROM.end();
    return 0;
  }

  const String AccessToken() const { return String(accessToken); }
private:
  const String ClientID_;
  const String ClientSecret_;

  // Token which, upon success, may be used to
  // access authorized APIs
  char accessToken[256]{};
  char refreshToken[256]{};
  unsigned long expirationMs = 0;
};

// TODO(smklein): Maybe move somewhere else...
String sendPostCommand(WiFiClientSecure& client,
                       const String& host, int port,
                       const String& endpoint, const String& command);

