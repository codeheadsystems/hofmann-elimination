package com.codeheadsystems.hofmann.client.model;

public record HofmannHashResult(ServerIdentifier serverIdentifier, String processIdentifier, String requestId, byte[] hash) {

}
