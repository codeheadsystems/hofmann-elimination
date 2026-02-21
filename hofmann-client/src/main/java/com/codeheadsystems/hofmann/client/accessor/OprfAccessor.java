package com.codeheadsystems.hofmann.client.accessor;

import com.codeheadsystems.hofmann.client.config.OprfConfig;
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
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Singleton
public class OprfAccessor {
  private static final Logger log = LoggerFactory.getLogger(OprfAccessor.class);

  private final HttpClient httpClient;
  private final ObjectMapper objectMapper;
  private final Map<ServerIdentifier, ServerConnectionInfo> serverConnections;

  @Inject
  public OprfAccessor(final OprfConfig oprfConfig,
                      final HttpClient httpClient,
                      final ObjectMapper objectMapper,
                      final Map<ServerIdentifier, ServerConnectionInfo> serverConnections) {
    log.info("OprfAccessor({})", oprfConfig);
    this.httpClient = httpClient;
    this.objectMapper = objectMapper;
    this.serverConnections = serverConnections;
  }

  public Response handleRequest(final ServerIdentifier serverIdentifier,
                                final String requestId,
                                final byte[] blindedElement) {
    log.trace("handleRequest(requestId={}, serverIdentifier={})", serverIdentifier, requestId);

    final ServerConnectionInfo connectionInfo = serverConnections.get(serverIdentifier);
    if (connectionInfo == null) {
      throw new IllegalArgumentException("No connection info for server: " + serverIdentifier);
    }

    final String blindedPointHex = Hex.toHexString(blindedElement);
    final OprfRequest oprfRequest = new OprfRequest(blindedPointHex, requestId);

    try {
      final String requestBody = objectMapper.writeValueAsString(oprfRequest);
      final HttpRequest httpRequest = HttpRequest.newBuilder()
          .uri(connectionInfo.endpoint())
          .header("Content-Type", "application/json")
          .POST(HttpRequest.BodyPublishers.ofString(requestBody))
          .build();

      final HttpResponse<String> httpResponse = httpClient.send(httpRequest, HttpResponse.BodyHandlers.ofString());

      final OprfResponse response = objectMapper.readValue(httpResponse.body(), OprfResponse.class);
      final byte[] evaluatedElement = Hex.decode(response.ecPoint());
      return new Response(evaluatedElement, response.processIdentifier());
    } catch (IOException e) {
      throw new OprfAccessorException("HTTP request failed for server: " + serverIdentifier, e);
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      throw new OprfAccessorException("HTTP request interrupted for server: " + serverIdentifier, e);
    }
  }

  public record Response(byte[] evaluatedElement, String processIdentifier) {
  }

}
