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
import com.google.common.collect.Lists;
import com.google.common.collect.Maps;

import com.heartbleed.HeartbleedScanner;
import com.heartbleed.HeartbleedScanner.ScanMode;

import java.util.List;
import java.util.Map;

public class BurpExtender implements IBurpExtender, IScannerCheck {

  private final Map<String, Boolean> hostVulnerabilityMap;

  public BurpExtender() {
    this.hostVulnerabilityMap = Maps.newHashMap();
  }

  private String keyForService(IHttpService service) {
    return service.getProtocol() + "://" + service.getHost().toLowerCase() + ":" +
        service.getPort();
  }

  @Override
  public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
    Preconditions.checkNotNull(callbacks);
    callbacks.registerScannerCheck(this);
  }

  private List<IScanIssue> doScan(IHttpService service) {
    Preconditions.checkNotNull(service);
    List<IScanIssue> results = null;

    if (!service.getProtocol().equalsIgnoreCase("https")) {
      return results;
    }

    String hostKey = keyForService(service);
    if (hostVulnerabilityMap.containsKey(hostKey)) {
      return results;
    }

    ScanMode mode = HeartbleedScanner.getScanMode();
    boolean vulnerable = HeartbleedScanner.testHostForHeartbleed(
        service.getHost(), service.getPort(), mode);
    hostVulnerabilityMap.put(hostKey, vulnerable);
    if (vulnerable) {
      results = Lists.newArrayList();
      results.add(new HeartbleedIssue(service, mode));
    }
    return results;
  }

  // TODO: determine if this is actually an appropriate 'passive' check to run.
  @Override
  public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {
    return doScan(baseRequestResponse.getHttpService());
  }

  @Override
  public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse,
      IScannerInsertionPoint insertionPoint) {
    return doScan(baseRequestResponse.getHttpService());
  }

  @Override
  public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
    if (existingIssue.getIssueName().equalsIgnoreCase(newIssue.getIssueName())) {
      return -1;
    }
    return 0;
  }

}
