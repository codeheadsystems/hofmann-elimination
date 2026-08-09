package com.codeheadsystems.hofmann.client.model;

/**
 * Names one Hofmann server a client talks to. Used as the key into the client's map of server
 * connections, so the value is client-side and arbitrary — it needs only to be stable and distinct
 * per server, not to match anything the server itself reports.
 *
 * @param id the client-chosen name for the server
 */
public record ServerIdentifier(String id) {
}
