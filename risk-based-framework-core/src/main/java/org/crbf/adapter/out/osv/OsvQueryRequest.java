package org.crbf.adapter.out.osv;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonInclude;

record OsvQueryRequest(String version, @JsonProperty("package") Package pkg,
        @JsonProperty("page_token") @JsonInclude(JsonInclude.Include.NON_NULL) String pageToken) {
    record Package(String name, String ecosystem) {}
}