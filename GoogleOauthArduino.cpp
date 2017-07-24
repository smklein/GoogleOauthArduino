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

#include "GoogleOauthArduino.h"
#include <ArduinoJson.h>

int GoogleAuthenticator::QueryUserCode(WiFiClientSecure& client, const String& Scope,
                                       GoogleAuthRequest* out) {
  Serial.println("Querying for device and user codes");

  String command = "client_id=" + ClientID_ + "&scope=" + Scope;
  String responseString = sendPostCommand(client, GACCOUNT_HOST, GACCOUNT_SSL_PORT,
                                          "/o/oauth2/device/code", command);
  if (responseString == "") {
    Serial.println("Failed to send request to server");
    return -1;
  }

  Serial.println("Response from POST: ");
  Serial.println(responseString);

  DynamicJsonBuffer jsonBuffer;
  JsonObject& response = jsonBuffer.parseObject(responseString);
  if (!response.success()) {
    Serial.println("Failed to parse response");
    return -1;
  }
  Serial.println("Parsed JSON successfully");
  if (!response.containsKey("device_code") ||
      !response.containsKey("user_code") ||
      !response.containsKey("verification_url") ||
      !response.containsKey("expires_in") ||
      !response.containsKey("interval")) {
    Serial.println("JSON does not contain desired codes");
    return -1;
  }
  strncpy(out->oauthDeviceCode, response["device_code"], sizeof(out->oauthDeviceCode));
  strncpy(out->oauthUserCode, response["user_code"], sizeof(out->oauthUserCode));
  strncpy(out->verifyURL, response["verification_url"], sizeof(out->verifyURL));

  auto now = millis();
  out->expirationMs = now + response["expires_in"].as<unsigned long>() * 1000;
  out->intervalMs = response["interval"].as<unsigned long>() * 1000;
  out->nextMs = now + out->intervalMs;

  Serial.print("Device Code: ");
  Serial.println(String(out->oauthDeviceCode));

  Serial.print("User Code: ");
  Serial.println(String(out->oauthUserCode));

  Serial.print("Verify URL: ");
  Serial.println(String(out->verifyURL));

  // https://developers.google.com/identity/protocols/OAuth2ForDevices
  return 0;
}

int GoogleAuthenticator::QueryAccessToken(WiFiClientSecure& client,
                                          GoogleAuthRequest* authRequest) {
  auto now = millis();
  if (now < authRequest->nextMs) {
    return -1;
  } else if (now > authRequest->expirationMs) {
    Serial.println("Skipping polling request; expired...");
    return -1;
  }
  Serial.println("Polling for authentication confirmation, access token");
  authRequest->nextMs = now + authRequest->intervalMs;

  String command =
    "client_id=" + ClientID_ + \
    "&client_secret=" + ClientSecret_ + \
    "&grant_type=http://oauth.net/grant_type/device/1.0" + \
    "&code=" + authRequest->DeviceCode();
  String responseString = sendPostCommand(client, GAPI_HOST, GAPI_SSL_PORT,
                                          "/oauth2/v4/token", command);

  if (responseString == "") {
    return -1;
  }

  DynamicJsonBuffer jsonBuffer;
  JsonObject& response = jsonBuffer.parseObject(responseString);
  if (!response.success()) {
    Serial.println("Failed to parse response");
    return -1;
  }
  Serial.println("Parsed JSON successfully");

  if (response.containsKey("error")) {
    String responseError = response["error"];
    Serial.print("Cannot acquire access token due to error: ");
    Serial.println(responseError);
    return -1;
  }

  if (!response.containsKey("access_token") ||
      !response.containsKey("refresh_token") ||
      !response.containsKey("expires_in")) {
    Serial.println("Response does not contain access token\n");
    return -1;
  }
  strncpy(accessToken, response["access_token"], sizeof(accessToken));
  strncpy(refreshToken, response["refresh_token"], sizeof(refreshToken));
  expirationMs = millis() + response["expires_in"].as<unsigned long>() * 1000;

  Serial.print("Access Token: ");
  Serial.println(String(accessToken));
  Serial.print("Expiration time: ");
  Serial.println(response["expires_in"].as<String>());
  /*
     https://developers.google.com/identity/protocols/OAuth2ForDevices
     TODO(smklein): Parse the following
     - "refresh_token": Mechanism to refresh access token
        TODO: do this too; store in EEPROM?
        https://github.com/esp8266/Arduino/blob/master/libraries/EEPROM
   */
  return 0;
}

int GoogleAuthenticator::QueryRefresh(WiFiClientSecure& client) {
  auto now = millis();
  if (now < expirationMs) {
    return -1;
  }
  Serial.println("Refreshing Token");

  String command =
    "client_id=" + ClientID_ + \
    "&client_secret=" + ClientSecret_ + \
    "&refresh_token=" + String(refreshToken) + \
    "&grant_type=refresh_token";
  String responseString = sendPostCommand(client, GAPI_HOST, GAPI_SSL_PORT,
                                          "/oauth2/v4/token", command);
  if (responseString == "") {
    return -1;
  }

  DynamicJsonBuffer jsonBuffer;
  JsonObject& response = jsonBuffer.parseObject(responseString);
  if (!response.success()) {
    Serial.println("Failed to parse response");
    return -1;
  }
  Serial.println("Parsed JSON successfully");

  if (response.containsKey("error")) {
    String responseError = response["error"];
    Serial.print("Cannot refresh token due to error: ");
    Serial.println(responseError);
    return -1;
  }

  if (!response.containsKey("access_token") ||
      !response.containsKey("expires_in")) {
    Serial.println("Response does not contain access token\n");
    return -1;
  }
  strncpy(accessToken, response["access_token"], sizeof(accessToken));
  expirationMs = millis() + response["expires_in"].as<unsigned long>() * 1000;

  Serial.print("Access Token: ");
  Serial.println(String(accessToken));
  return 0;
}

String sendPostCommand(WiFiClientSecure& client,
                       const String& host, int port,
                       const String& endpoint, const String& command) {
  if (!client.connect(host.c_str(), port)) {
    return "";
  }
  client.println("POST " + endpoint + " HTTP/1.1");
  client.println("Host: " + host);
  client.println("User-Agent: Arduino/1.0");
  client.print("Content-Length: ");
  client.println(command.length());
  client.println("Content-Type: application/x-www-form-urlencoded");
  client.println();
  client.println(command);


  // TODO(smklein): Technically, we shouldn't be reading chunks unless
  // we see "Transfer-Encoding: chunked" in the header...
  bool reading_header = true;
  bool reading_chunk = false;
  String header = "";
  String chunkLen = "";
  String body = "";

  long start = millis();
  while (millis() - start < 1500) {
    while (client.available()) {
      char c = client.read();
      if (reading_header) {
        header += c;
      } else if (reading_chunk) {
        chunkLen += c;
      } else {
        body += c;
      }

      if (reading_header && header.endsWith("\r\n\r\n")) {
        reading_header = false;
        reading_chunk = true;
      } else if (reading_chunk && chunkLen.endsWith("\r\n")) {
        reading_chunk = false;
        chunkLen = "";
      } else if (!reading_header && !reading_chunk && body.endsWith("\r\n")) {
        reading_chunk = true;
        body.trim();
      }
    }
    if (header != "" || body != "") {
      break;
    }
  }
  Serial.println("Message received from query: ");
  Serial.println(header);
  Serial.println("---");
  Serial.println(body);
  return body;
}
