package com.codeheadsystems.hofmann.client.accessor;

import com.codeheadsystems.hofmann.client.config.OprfClientConfig;
import com.codeheadsystems.hofmann.client.exceptions.OprfAccessorException;
import com.codeheadsystems.hofmann.client.exceptions.OprfModeNotEnabledException;
import com.codeheadsystems.hofmann.client.exceptions.OprfRateLimitedException;
import com.codeheadsystems.hofmann.client.exceptions.OprfRequestTooLargeException;
import com.codeheadsystems.hofmann.client.model.ServerConnectionInfo;
import com.codeheadsystems.hofmann.client.model.ServerIdentifier;
import com.codeheadsystems.hofmann.model.oprf.OprfClientConfigResponse;
import com.codeheadsystems.hofmann.model.oprf.OprfRequest;
import com.codeheadsystems.hofmann.model.oprf.OprfResponse;
import com.codeheadsystems.hofmann.model.oprf.PoprfRequest;
import com.codeheadsystems.hofmann.model.oprf.PoprfResponse;
import com.codeheadsystems.hofmann.model.oprf.VoprfRequest;
import com.codeheadsystems.hofmann.model.oprf.VoprfResponse;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Map;
import javax.inject.Inject;
import javax.inject.Singleton;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The type Hofmann oprf accessor.
 */
@Singleton
public class HofmannOprfAccessor {
  private static final Logger log = LoggerFactory.getLogger(HofmannOprfAccessor.class);

  private static final String OPRF_BASE_SEGMENT = "/oprf";

  private final HttpClient httpClient;
  private final ObjectMapper objectMapper;
  private final Map<ServerIdentifier, ServerConnectionInfo> serverConnections;

  /**
   * Instantiates a new Hofmann oprf accessor.
   *
   * @param oprfClientConfig  the oprf client config
   * @param httpClient        the http client
   * @param objectMapper      the object mapper
   * @param serverConnections the server connections
   */
  @Inject
  public HofmannOprfAccessor(final OprfClientConfig oprfClientConfig,
                             final HttpClient httpClient,
                             final ObjectMapper objectMapper,
                             final Map<ServerIdentifier, ServerConnectionInfo> serverConnections) {
    log.info("OprfAccessor({})", oprfClientConfig);
    this.httpClient = httpClient;
    this.objectMapper = objectMapper;
    this.serverConnections = serverConnections;
  }

  /**
   * Resolves an OPRF sub-path against a server's configured endpoint.
   *
   * <p>Two conventions for {@code endpoint()} exist in the wild and both must work: the server
   * root, which {@code HofmannOpaqueAccessor} assumes, and the OPRF base
   * {@code http://host:port/oprf}, which every caller in this repository configures. This method
   * appends {@code /oprf} only when the path does not already end in it.
   *
   * <p>It replaces two call sites that disagreed. {@code getOprfConfig} used to build
   * {@code endpoint().resolve(endpoint().getPath() + "/oprf/config")}, which for the
   * {@code .../oprf} base every caller uses resolved to {@code /oprf/oprf/config}; nothing caught
   * it because every caller also passes a config override, so the auto-fetch path never ran
   * against a live server. {@code handleRequest} meanwhile POSTed to {@code endpoint()} verbatim,
   * which required the base to already be {@code .../oprf} and 404'd against a root endpoint.
   *
   * <p>A deployment that mounts the resource at a path not ending in {@code /oprf} sets
   * {@link ServerConnectionInfo#oprfBasePath()} and this inference is skipped.
   *
   * @param info    the server connection info
   * @param subPath the sub-path, empty for the evaluate endpoint itself
   * @return the resolved URI
   */
  static URI oprfUri(final ServerConnectionInfo info, final String subPath) {
    String base = info.oprfBasePath();
    if (base == null) {
      String path = info.endpoint().getPath() == null ? "" : info.endpoint().getPath();
      // A loop rather than a single strip: "http://host/oprf//" is unusual but resolves wrong
      // rather than failing, which is the kind of thing that reaches production.
      while (path.endsWith("/")) {
        path = path.substring(0, path.length() - 1);
      }
      base = path.endsWith(OPRF_BASE_SEGMENT) ? path : path + OPRF_BASE_SEGMENT;
    }
    return info.endpoint().resolve(base + subPath);
  }

  /**
   * Fetches the OPRF configuration from the server.
   *
   * @param serverIdentifier the server identifier
   * @return the oprf client config response
   */
  public OprfClientConfigResponse getOprfConfig(final ServerIdentifier serverIdentifier) {
    log.debug("getOprfConfig(serverIdentifier={})", serverIdentifier);
    final ServerConnectionInfo connectionInfo = connectionInfo(serverIdentifier);
    return get(serverIdentifier, oprfUri(connectionInfo, "/config"), OprfClientConfigResponse.class);
  }

  /**
   * Handle request oprf response.
   *
   * @param serverIdentifier the server identifier
   * @param oprfRequest      the oprf request
   * @return the oprf response
   */
  public OprfResponse handleRequest(final ServerIdentifier serverIdentifier,
                                    final OprfRequest oprfRequest) {
    log.trace("handleRequest(requestId={}, serverIdentifier={})", serverIdentifier, oprfRequest.requestId());
    return post(serverIdentifier, oprfUri(connectionInfo(serverIdentifier), ""),
        oprfRequest, OprfResponse.class, "OPRF");
  }

  /**
   * Evaluates a batch of blinded elements under the server's VOPRF key (RFC 9497 mode 0x01).
   *
   * <p>The response carries one DLEQ proof covering the whole batch. This method does not verify
   * it — that is {@code VoprfClientManager.hashResults}' job, and it needs the pinned public key
   * and the blinding factors, neither of which belongs in a transport class.
   *
   * @param serverIdentifier the server identifier
   * @param request          the batched blinded request
   * @return the evaluated elements and the proof
   * @throws OprfModeNotEnabledException if the server has no VOPRF key configured
   */
  public VoprfResponse handleVerifiableRequest(final ServerIdentifier serverIdentifier,
                                               final VoprfRequest request) {
    log.trace("handleVerifiableRequest(requestId={}, serverIdentifier={})",
        request.requestId(), serverIdentifier);
    return post(serverIdentifier, oprfUri(connectionInfo(serverIdentifier), "/verifiable"),
        request, VoprfResponse.class, "VOPRF");
  }

  /**
   * Evaluates a batch of blinded elements under a key tweaked by the request's public input
   * (RFC 9497 mode 0x02).
   *
   * @param serverIdentifier the server identifier
   * @param request          the batched partially-blinded request
   * @return the evaluated elements and the proof
   * @throws OprfModeNotEnabledException if the server has no POPRF key configured
   */
  public PoprfResponse handlePartiallyObliviousRequest(final ServerIdentifier serverIdentifier,
                                                       final PoprfRequest request) {
    log.trace("handlePartiallyObliviousRequest(requestId={}, serverIdentifier={})",
        request.requestId(), serverIdentifier);
    return post(serverIdentifier, oprfUri(connectionInfo(serverIdentifier), "/partially-oblivious"),
        request, PoprfResponse.class, "POPRF");
  }

  private ServerConnectionInfo connectionInfo(final ServerIdentifier serverIdentifier) {
    final ServerConnectionInfo connectionInfo = serverConnections.get(serverIdentifier);
    if (connectionInfo == null) {
      throw new IllegalArgumentException("No connection info for server: " + serverIdentifier);
    }
    return connectionInfo;
  }

  private <T> T post(final ServerIdentifier serverIdentifier,
                     final URI uri,
                     final Object body,
                     final Class<T> responseType,
                     final String mode) {
    try {
      final String requestBody = objectMapper.writeValueAsString(body);
      final HttpRequest httpRequest = HttpRequest.newBuilder()
          .uri(uri)
          .header("Content-Type", "application/json")
          .POST(HttpRequest.BodyPublishers.ofString(requestBody))
          .build();

      final HttpResponse<String> httpResponse = httpClient.send(httpRequest, HttpResponse.BodyHandlers.ofString());
      checkStatus(serverIdentifier, httpResponse, mode);
      return objectMapper.readValue(httpResponse.body(), responseType);
    } catch (IOException e) {
      throw new OprfAccessorException("HTTP request failed for server: " + serverIdentifier, e);
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      throw new OprfAccessorException("HTTP request interrupted for server: " + serverIdentifier, e);
    }
  }

  private <T> T get(ServerIdentifier serverIdentifier, URI uri, Class<T> responseType) {
    try {
      final HttpRequest httpRequest = HttpRequest.newBuilder()
          .uri(uri)
          .header("Accept", "application/json")
          .GET()
          .build();
      final HttpResponse<String> httpResponse = httpClient.send(httpRequest, HttpResponse.BodyHandlers.ofString());
      checkStatus(serverIdentifier, httpResponse, "OPRF");
      return objectMapper.readValue(httpResponse.body(), responseType);
    } catch (IOException e) {
      throw new OprfAccessorException("HTTP request failed for server: " + serverIdentifier, e);
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      throw new OprfAccessorException("HTTP request interrupted for server: " + serverIdentifier, e);
    }
  }

  private void checkStatus(final ServerIdentifier serverIdentifier,
                           final HttpResponse<String> response,
                           final String mode) {
    final int statusCode = response.statusCode();
    if (statusCode == 401) {
      throw new SecurityException("Server rejected request (401) for server: " + serverIdentifier);
    }
    if (statusCode == 404) {
      // The verifiable endpoints answer 404 when the deployment has no key for that mode. The
      // base-mode path can also 404 on a misconfigured base URL, so the message names both.
      throw new OprfModeNotEnabledException(
          mode + " is not enabled on server " + serverIdentifier + " (404), or the configured "
              + "endpoint does not point at its OPRF resource");
    }
    if (statusCode == 413) {
      throw new OprfRequestTooLargeException(
          "Server " + serverIdentifier + " rejected the request body as too large (413); for the "
              + "verifiable modes the bound is derived from the batch cap");
    }
    if (statusCode == 429) {
      throw new OprfRateLimitedException(
          "Server " + serverIdentifier + " rate limited this client (429)",
          retryAfter(response));
    }
    if (statusCode >= 400) {
      throw new OprfAccessorException(
          "Server returned HTTP " + statusCode + " for server: " + serverIdentifier, null);
    }
  }

  /**
   * Parses {@code Retry-After} as delta-seconds. The HTTP-date form is not handled: nothing in
   * this project emits it, and a null return means "no guidance", which is the safe reading of a
   * header we could not understand.
   */
  private Duration retryAfter(final HttpResponse<String> response) {
    return response.headers().firstValue("Retry-After")
        .map(value -> {
          try {
            return Duration.ofSeconds(Long.parseLong(value.trim()));
          } catch (NumberFormatException e) {
            log.debug("Unparseable Retry-After header: {}", value);
            return null;
          }
        })
        .orElse(null);
  }

}
