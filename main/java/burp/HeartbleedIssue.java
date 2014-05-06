/*
 * Copyright 2014 Google Inc. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 */
package burp;

import com.google.common.base.Preconditions;
import com.google.common.base.Throwables;

import com.heartbleed.HeartbleedScanner.ScanMode;

import java.net.MalformedURLException;
import java.net.URL;

public class HeartbleedIssue implements IScanIssue {

  private URL url;
  private IHttpService service;
  private final ScanMode mode;

  public HeartbleedIssue(IHttpService service, ScanMode mode) {
    this.service = Preconditions.checkNotNull(service);
    this.mode = Preconditions.checkNotNull(mode);
    try {
      this.url = new URL("https", service.getHost().toLowerCase(), service.getPort(), "");
    } catch (MalformedURLException e) {
      Throwables.propagate(e);
    }
  }

  @Override
  public URL getUrl() {
    return url;
  }

  @Override
  public String getIssueName() {
    return url.toString() + " vulnerable to HeartBleed";
  }

  // See http://portswigger.net/burp/help/scanner_issuetypes.html
  @Override
  public int getIssueType() {
    return 134217728;
  }

  @Override
  public String getSeverity() {
    return "High";
  }

  @Override
  public String getConfidence() {
    if (mode.equals(ScanMode.INTRUSIVE)) {
      return "Firm";
    }
    return "Tentative";
  }

  @Override
  public String getIssueBackground() {
    return "See CVE-2014-0160 [http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-0160]";
  }

  @Override
  public String getRemediationBackground() {
    return "Upgrade to a non-vulnerable version of OpenSSL.";
  }

  @Override
  public String getIssueDetail() {
    return "See CVE-2014-0160 [http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-0160]";
  }

  @Override
  public String getRemediationDetail() {
    return "Upgrade to a non-vulnerable version of OpenSSL.";
  }

  @Override
  public IHttpRequestResponse[] getHttpMessages() {
    return null;
  }

  @Override
  public IHttpService getHttpService() {
    return service;
  }

}
