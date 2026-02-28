package com.codeheadsystems.hofmann.testserver.cli;

import com.codeheadsystems.hofmann.client.accessor.HofmannOprfAccessor;
import com.codeheadsystems.hofmann.client.config.OprfClientConfig;
import com.codeheadsystems.hofmann.client.manager.HofmannOprfClientManager;
import com.codeheadsystems.hofmann.client.model.HofmannHashResult;
import com.codeheadsystems.hofmann.client.model.ServerConnectionInfo;
import com.codeheadsystems.hofmann.client.model.ServerIdentifier;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.net.URI;
import java.net.http.HttpClient;
import java.util.HexFormat;
import java.util.Map;

/**
 * Command-line OPRF client for exercising the testserver's {@code POST /oprf} endpoint.
 *
 * <pre>
 * Usage:
 *   ./gradlew :hofmann-testserver:runOprfCli --args="&lt;input&gt; [--server &lt;url&gt;]" -q
 *
 * Examples:
 *   ./gradlew :hofmann-testserver:runOprfCli --args="my-sensitive-data" -q
 *   ./gradlew :hofmann-testserver:runOprfCli --args="my-sensitive-data --server http://localhost:9090" -q
 * </pre>
 *
 * <p>The same input produces the same hash on every call as long as the server's OPRF master
 * key has not changed. Different inputs produce different hashes. This is the core OPRF
 * property the tool is designed to demonstrate.
 */
public class OprfCli {

  private static final ServerIdentifier SERVER_ID = new ServerIdentifier("testserver");
  private static final String DEFAULT_SERVER = "http://localhost:8080";

  /**
   * Main entry point.
   *
   * @param args command-line arguments
   */
  public static void main(String[] args) {
    String server = DEFAULT_SERVER;
    String input = null;

    for (int i = 0; i < args.length; i++) {
      if ("--server".equals(args[i]) && i + 1 < args.length) {
        server = args[++i];
      } else if (!args[i].startsWith("-")) {
        input = args[i];
      }
    }

    if (input == null) {
      System.err.println("Usage: OprfCli [--server <url>] <input>");
      System.err.println();
      System.err.println("  --server <url>   Server base URL (default: " + DEFAULT_SERVER + ")");
      System.err.println();
      System.err.println("Example:");
      System.err.println("  ./gradlew :hofmann-testserver:runOprfCli --args=\"my-sensitive-data\" -q");
      System.exit(1);
    }

    OprfClientConfig oprfClientConfig = new OprfClientConfig();
    Map<ServerIdentifier, ServerConnectionInfo> connections = Map.of(
        SERVER_ID, new ServerConnectionInfo(URI.create(server + "/oprf")));
    HofmannOprfAccessor accessor = new HofmannOprfAccessor(
        oprfClientConfig, HttpClient.newHttpClient(), new ObjectMapper(), connections);
    HofmannOprfClientManager manager = new HofmannOprfClientManager(accessor, Map.of(SERVER_ID, oprfClientConfig));

    System.out.println("Server : " + server);
    System.out.println("Input  : " + input);
    System.out.println();

    try {
      HofmannHashResult result = manager.performHash(input, SERVER_ID);
      System.out.println("Result:");
      System.out.println("  processor  : " + result.processIdentifier());
      System.out.println("  request-id : " + result.requestId());
      System.out.println("  hash (hex) : " + HexFormat.of().formatHex(result.hash()));
    } catch (Exception e) {
      System.err.println("Error: " + e.getMessage());
      System.exit(1);
    }
  }
}
