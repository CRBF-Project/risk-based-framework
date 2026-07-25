package org.crbf.adapter.out.osv;

import com.fasterxml.jackson.annotation.JsonProperty;

record OsvQueryRequest(String version, @JsonProperty("package") Package pkg) {
    record Package(String name, String ecosystem) {}
}