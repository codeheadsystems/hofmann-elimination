package com.codeheadsystems.hofmann.client.accessor;

import com.codeheadsystems.hofmann.client.exceptions.OpaqueAccessorException;
import com.codeheadsystems.hofmann.client.model.ServerConnectionInfo;
import com.codeheadsystems.hofmann.client.model.ServerIdentifier;
import com.codeheadsystems.hofmann.model.opaque.AuthFinishRequest;
import com.codeheadsystems.hofmann.model.opaque.AuthFinishResponse;
import com.codeheadsystems.hofmann.model.opaque.AuthStartRequest;
import com.codeheadsystems.hofmann.model.opaque.AuthStartResponse;
import com.codeheadsystems.hofmann.model.opaque.OpaqueClientConfigResponse;
import com.codeheadsystems.hofmann.model.opaque.RegistrationDeleteRequest;
import com.codeheadsystems.hofmann.model.opaque.RegistrationFinishRequest;
import com.codeheadsystems.hofmann.model.opaque.RegistrationStartRequest;
import com.codeheadsystems.hofmann.model.opaque.RegistrationStartResponse;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Map;
import javax.inject.Inject;
import javax.inject.Singleton;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * HTTP client for the OPAQUE REST endpoints exposed by {@code hofmann-server}.
 * <p>
 * Handles request serialization, HTTP dispatch, status-code checking, and response
 * deserialization for all five OPAQUE endpoints.  The {@code endpoint} stored in
 * {@link ServerConnectionInfo} is treated as the <em>base URL</em> of the server
 * (e.g. {@code http://host:8080}); path segments are appended per endpoint.
 * <p>
 * A 401 response from any endpoint is surfaced as a {@link SecurityException}.
 * I/O errors and interruptions are wrapped in {@link OpaqueAccessorException}.
 */
@Singleton
public class HofmannOpaqueAccessor {

  private static final Logger log = LoggerFactory.getLogger(HofmannOpaqueAccessor.class);

  private final HttpClient httpClient;
  private final ObjectMapper objectMapper;
  private final Map<ServerIdentifier, ServerConnectionInfo> serverConnections;

  /**
   * Instantiates a new Hofmann opaque accessor.
   *
   * @param httpClient        the http client
   * @param objectMapper      the object mapper
   * @param serverConnections the server connections
   */
  @Inject
  public HofmannOpaqueAccessor(final HttpClient httpClient,
                               final ObjectMapper objectMapper,
                               final Map<ServerIdentifier, ServerConnectionInfo> serverConnections) {
    log.info("OpaqueAccessor()");
    this.httpClient = httpClient;
    this.objectMapper = objectMapper;
    this.serverConnections = serverConnections;
  }

  // ── Config ────────────────────────────────────────────────────────────────

  /**
   * Fetches the OPAQUE configuration from the server.
   *
   * @param serverId the server id
   * @return the opaque client config response
   */
  public OpaqueClientConfigResponse getOpaqueConfig(final ServerIdentifier serverId) {
    log.debug("getOpaqueConfig(serverId={})", serverId);
    URI uri = baseUri(serverId).resolve(baseUri(serverId).getPath() + "/opaque/config");
    return get(serverId, uri, OpaqueClientConfigResponse.class);
  }

  // ── Registration ─────────────────────────────────────────────────────────

  /**
   * Phase 1 of registration: sends the blinded element to the server and returns the
   * OPRF-evaluated element plus the server's public key.
   *
   * @param serverId the server id
   * @param request  the request
   * @return the registration start response
   */
  public RegistrationStartResponse registrationStart(final ServerIdentifier serverId,
                                                     final RegistrationStartRequest request) {
    log.debug("registrationStart(serverId={})", serverId);
    URI uri = baseUri(serverId).resolve(baseUri(serverId).getPath() + "/opaque/registration/start");
    return post(serverId, uri, request, RegistrationStartResponse.class);
  }

  /**
   * Phase 2 of registration: uploads the completed registration record to the server.
   *
   * @param serverId the server id
   * @param request  the request
   */
  public void registrationFinish(final ServerIdentifier serverId,
                                 final RegistrationFinishRequest request) {
    log.debug("registrationFinish(serverId={})", serverId);
    URI uri = baseUri(serverId).resolve(baseUri(serverId).getPath() + "/opaque/registration/finish");
    postNoContent(serverId, uri, request);
  }

  /**
   * Deletes a previously registered credential from the server.
   * Requires a valid JWT bearer token for authentication and ownership verification.
   *
   * @param serverId    the server to delete from
   * @param request     the delete request containing the credential identifier
   * @param bearerToken the JWT bearer token (without "Bearer " prefix)
   */
  public void registrationDelete(final ServerIdentifier serverId,
                                 final RegistrationDeleteRequest request,
                                 final String bearerToken) {
    log.debug("registrationDelete(serverId={})", serverId);
    URI uri = baseUri(serverId).resolve(baseUri(serverId).getPath() + "/opaque/registration");
    deleteNoContent(serverId, uri, request, bearerToken);
  }

  // ── Authentication ────────────────────────────────────────────────────────

  /**
   * AKE phase 1: sends KE1 to the server and returns KE2 (plus the session token).
   *
   * @param serverId the server id
   * @param request  the request
   * @return the auth start response
   */
  public AuthStartResponse authStart(final ServerIdentifier serverId,
                                     final AuthStartRequest request) {
    log.debug("authStart(serverId={})", serverId);
    URI uri = baseUri(serverId).resolve(baseUri(serverId).getPath() + "/opaque/auth/start");
    return post(serverId, uri, request, AuthStartResponse.class);
  }

  /**
   * AKE phase 2: sends KE3 to the server and returns the shared session key.
   *
   * @param serverId the server id
   * @param request  the request
   * @return the auth finish response
   * @throws SecurityException if the server rejects the client MAC (HTTP 401)
   */
  public AuthFinishResponse authFinish(final ServerIdentifier serverId,
                                       final AuthFinishRequest request) {
    log.debug("authFinish(serverId={})", serverId);
    URI uri = baseUri(serverId).resolve(baseUri(serverId).getPath() + "/opaque/auth/finish");
    return post(serverId, uri, request, AuthFinishResponse.class);
  }

  // ── Helpers ───────────────────────────────────────────────────────────────

  private <T> T get(ServerIdentifier serverId, URI uri, Class<T> responseType) {
    try {
      HttpRequest request = HttpRequest.newBuilder()
          .uri(uri)
          .header("Accept", "application/json")
          .GET()
          .build();
      HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
      checkStatus(serverId, response.statusCode());
      return objectMapper.readValue(response.body(), responseType);
    } catch (IOException e) {
      throw new OpaqueAccessorException("HTTP request failed for server: " + serverId, e);
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      throw new OpaqueAccessorException("HTTP request interrupted for server: " + serverId, e);
    }
  }

  private URI baseUri(ServerIdentifier serverId) {
    ServerConnectionInfo info = serverConnections.get(serverId);
    if (info == null) {
      throw new IllegalArgumentException("No connection info for server: " + serverId);
    }
    return info.endpoint();
  }

  private <T> T post(ServerIdentifier serverId, URI uri, Object body, Class<T> responseType) {
    try {
      String requestBody = objectMapper.writeValueAsString(body);
      HttpRequest request = HttpRequest.newBuilder()
          .uri(uri)
          .header("Content-Type", "application/json")
          .POST(HttpRequest.BodyPublishers.ofString(requestBody))
          .build();
      HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
      checkStatus(serverId, response.statusCode());
      return objectMapper.readValue(response.body(), responseType);
    } catch (IOException e) {
      throw new OpaqueAccessorException("HTTP request failed for server: " + serverId, e);
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      throw new OpaqueAccessorException("HTTP request interrupted for server: " + serverId, e);
    }
  }

  private void postNoContent(ServerIdentifier serverId, URI uri, Object body) {
    try {
      String requestBody = objectMapper.writeValueAsString(body);
      HttpRequest request = HttpRequest.newBuilder()
          .uri(uri)
          .header("Content-Type", "application/json")
          .POST(HttpRequest.BodyPublishers.ofString(requestBody))
          .build();
      HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
      checkStatus(serverId, response.statusCode());
    } catch (IOException e) {
      throw new OpaqueAccessorException("HTTP request failed for server: " + serverId, e);
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      throw new OpaqueAccessorException("HTTP request interrupted for server: " + serverId, e);
    }
  }

  private void deleteNoContent(ServerIdentifier serverId, URI uri, Object body, String bearerToken) {
    try {
      String requestBody = objectMapper.writeValueAsString(body);
      HttpRequest.Builder builder = HttpRequest.newBuilder()
          .uri(uri)
          .header("Content-Type", "application/json")
          .method("DELETE", HttpRequest.BodyPublishers.ofString(requestBody));
      if (bearerToken != null) {
        builder.header("Authorization", "Bearer " + bearerToken);
      }
      HttpResponse<String> response = httpClient.send(builder.build(), HttpResponse.BodyHandlers.ofString());
      checkStatus(serverId, response.statusCode());
    } catch (IOException e) {
      throw new OpaqueAccessorException("HTTP request failed for server: " + serverId, e);
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      throw new OpaqueAccessorException("HTTP request interrupted for server: " + serverId, e);
    }
  }

  private void checkStatus(ServerIdentifier serverId, int statusCode) {
    if (statusCode == 401) {
      throw new SecurityException("Server rejected request (401) for server: " + serverId);
    }
    if (statusCode >= 400) {
      throw new OpaqueAccessorException(
          "Server returned HTTP " + statusCode + " for server: " + serverId, null);
    }
  }
}
