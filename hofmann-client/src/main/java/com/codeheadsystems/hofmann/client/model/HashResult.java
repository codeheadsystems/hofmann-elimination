package com.codeheadsystems.hofmann.client.model;

public record HashResult(ServerIdentifier serverIdentifier, String processIdentifier, String requestId, byte[] hash) {
}
