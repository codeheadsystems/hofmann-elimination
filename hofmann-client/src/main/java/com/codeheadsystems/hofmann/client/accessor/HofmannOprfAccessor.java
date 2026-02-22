package com.codeheadsystems.hofmann.client.accessor;

import com.codeheadsystems.hofmann.client.config.OprfClientConfig;
import com.codeheadsystems.hofmann.client.exceptions.OprfAccessorException;
import com.codeheadsystems.hofmann.client.model.ServerConnectionInfo;
import com.codeheadsystems.hofmann.client.model.ServerIdentifier;
import com.codeheadsystems.hofmann.model.oprf.OprfRequest;
import com.codeheadsystems.hofmann.model.oprf.OprfResponse;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
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
   * Handle request oprf response.
   *
   * @param serverIdentifier the server identifier
   * @param oprfRequest      the oprf request
   * @return the oprf response
   */
  public OprfResponse handleRequest(final ServerIdentifier serverIdentifier,
                                    final OprfRequest oprfRequest) {
    log.trace("handleRequest(requestId={}, serverIdentifier={})", serverIdentifier, oprfRequest.requestId());

    final ServerConnectionInfo connectionInfo = serverConnections.get(serverIdentifier);
    if (connectionInfo == null) {
      throw new IllegalArgumentException("No connection info for server: " + serverIdentifier);
    }

    try {
      final String requestBody = objectMapper.writeValueAsString(oprfRequest);
      final HttpRequest httpRequest = HttpRequest.newBuilder()
          .uri(connectionInfo.endpoint())
          .header("Content-Type", "application/json")
          .POST(HttpRequest.BodyPublishers.ofString(requestBody))
          .build();

      final HttpResponse<String> httpResponse = httpClient.send(httpRequest, HttpResponse.BodyHandlers.ofString());
      checkStatus(serverIdentifier, httpResponse.statusCode());
      return objectMapper.readValue(httpResponse.body(), OprfResponse.class);
    } catch (IOException e) {
      throw new OprfAccessorException("HTTP request failed for server: " + serverIdentifier, e);
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      throw new OprfAccessorException("HTTP request interrupted for server: " + serverIdentifier, e);
    }
  }

  private void checkStatus(ServerIdentifier serverIdentifier, int statusCode) {
    if (statusCode == 401) {
      throw new SecurityException("Server rejected request (401) for server: " + serverIdentifier);
    }
    if (statusCode >= 400) {
      throw new OprfAccessorException(
          "Server returned HTTP " + statusCode + " for server: " + serverIdentifier, null);
    }
  }

}
