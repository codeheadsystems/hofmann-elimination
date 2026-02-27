package com.codeheadsystems.hofmann.testserver.cli;

import com.codeheadsystems.hofmann.client.accessor.HofmannOpaqueAccessor;
import com.codeheadsystems.hofmann.client.config.OpaqueClientConfig;
import com.codeheadsystems.hofmann.client.manager.HofmannOpaqueClientManager;
import com.codeheadsystems.hofmann.client.model.ServerConnectionInfo;
import com.codeheadsystems.hofmann.client.model.ServerIdentifier;
import com.codeheadsystems.hofmann.model.opaque.AuthFinishResponse;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Command-line OPAQUE client for exercising the testserver's registration and
 * authentication endpoints.
 *
 * <pre>
 * Usage:
 *   ./gradlew :hofmann-testserver:runOpaqueCli \
 *       --args="register|login|whoami &lt;credentialId&gt; &lt;password&gt; [options]" -q
 *
 * Commands:
 *   register   Register a credential with the server.
 *   login      Authenticate and print the session key and JWT token.
 *   whoami     Register, authenticate, then call GET /api/whoami with the JWT.
 *              Verifies the full OPAQUE + protected-endpoint round-trip.
 *
 * Options:
 *   --server &lt;url&gt;       Server base URL          (default: http://localhost:8080)
 *   --context &lt;string&gt;   OPAQUE context string    (default: hofmann-testserver)
 *   --memory &lt;kib&gt;       Argon2id memory in KiB   (default: 65536)
 *   --iterations &lt;n&gt;     Argon2id iterations      (default: 3)
 *   --parallelism &lt;n&gt;    Argon2id parallelism     (default: 1)
 *
 * Examples:
 *   ./gradlew :hofmann-testserver:runOpaqueCli --args="register alice@example.com hunter2" -q
 *   ./gradlew :hofmann-testserver:runOpaqueCli --args="login    alice@example.com hunter2" -q
 *   ./gradlew :hofmann-testserver:runOpaqueCli --args="whoami   alice@example.com hunter2" -q
 * </pre>
 *
 * <p>The --context, --memory, --iterations, and --parallelism options must match the
 * server's configuration exactly. The defaults match hofmann-testserver/config/config.yml.
 * See USAGE.md for details on why these parameters must be consistent.
 */
public class OpaqueCli {

  private static final ServerIdentifier SERVER_ID = new ServerIdentifier("testserver");
  private static final String DEFAULT_SERVER = "http://localhost:8080";
  private static final String DEFAULT_CONTEXT = "hofmann-testserver";
  private static final int DEFAULT_MEMORY = 65536;
  private static final int DEFAULT_ITERATIONS = 3;
  private static final int DEFAULT_PARALLELISM = 1;

  /**
   * Main entry point.
   *
   * @param args command-line arguments
   */
  public static void main(String[] args) {
    String server = DEFAULT_SERVER;
    String context = DEFAULT_CONTEXT;
    int memory = DEFAULT_MEMORY;
    int iterations = DEFAULT_ITERATIONS;
    int parallelism = DEFAULT_PARALLELISM;
    List<String> positional = new ArrayList<>();

    for (int i = 0; i < args.length; i++) {
      switch (args[i]) {
        case "--server"      -> server      = args[++i];
        case "--context"     -> context     = args[++i];
        case "--memory"      -> memory      = Integer.parseInt(args[++i]);
        case "--iterations"  -> iterations  = Integer.parseInt(args[++i]);
        case "--parallelism" -> parallelism = Integer.parseInt(args[++i]);
        default              -> positional.add(args[i]);
      }
    }

    if (positional.size() < 3) {
      printUsage();
      System.exit(1);
    }

    String command = positional.get(0);
    byte[] credentialId = positional.get(1).getBytes(StandardCharsets.UTF_8);
    byte[] password = positional.get(2).getBytes(StandardCharsets.UTF_8);

    OpaqueClientConfig config = OpaqueClientConfig.withArgon2id(
        "P256_SHA256", context, memory, iterations, parallelism);
    Map<ServerIdentifier, ServerConnectionInfo> connections = Map.of(
        SERVER_ID, new ServerConnectionInfo(URI.create(server)));
    HofmannOpaqueAccessor accessor = new HofmannOpaqueAccessor(
        HttpClient.newHttpClient(), new ObjectMapper(), connections);
    HofmannOpaqueClientManager manager = new HofmannOpaqueClientManager(config, accessor);

    System.out.println("Server  : " + server);
    System.out.println("Context : " + context);
    System.out.println("Argon2id: memory=" + memory + " KiB, iterations=" + iterations
        + ", parallelism=" + parallelism);
    System.out.println();

    try {
      switch (command) {
        case "register" -> runRegister(manager, credentialId, password);
        case "login"    -> runLogin(manager, credentialId, password);
        case "whoami"   -> runWhoami(manager, server, credentialId, password);
        default -> {
          System.err.println("Unknown command: " + command);
          printUsage();
          System.exit(1);
        }
      }
    } catch (SecurityException e) {
      System.err.println("Security failure (wrong password or server mismatch): " + e.getMessage());
      System.exit(2);
    } catch (Exception e) {
      System.err.println("Error: " + e.getMessage());
      System.exit(1);
    }
  }

  private static void runRegister(HofmannOpaqueClientManager manager,
                                  byte[] credentialId, byte[] password) {
    System.out.println("Registering credential...");
    manager.register(SERVER_ID, credentialId, password);
    System.out.println("Registration successful.");
  }

  private static void runLogin(HofmannOpaqueClientManager manager,
                               byte[] credentialId, byte[] password) {
    System.out.println("Authenticating...");
    AuthFinishResponse resp = manager.authenticate(SERVER_ID, credentialId, password);
    System.out.println("Authentication successful.");
    System.out.println("  session key : " + resp.sessionKeyBase64());
    System.out.println("  JWT token   : " + resp.token());
  }

  private static void runWhoami(HofmannOpaqueClientManager manager, String server,
                                byte[] credentialId, byte[] password)
      throws IOException, InterruptedException {
    System.out.println("Registering credential...");
    manager.register(SERVER_ID, credentialId, password);
    System.out.println("Authenticating...");
    AuthFinishResponse resp = manager.authenticate(SERVER_ID, credentialId, password);
    System.out.println("Authentication successful.");
    System.out.println("Calling GET /api/whoami with JWT...");

    HttpRequest request = HttpRequest.newBuilder()
        .uri(URI.create(server + "/api/whoami"))
        .header("Authorization", "Bearer " + resp.token())
        .GET()
        .build();
    HttpResponse<String> response = HttpClient.newHttpClient()
        .send(request, HttpResponse.BodyHandlers.ofString());

    System.out.println("  HTTP status : " + response.statusCode());
    System.out.println("  Body        : " + response.body());

    if (response.statusCode() != 200) {
      System.err.println("Unexpected status code: " + response.statusCode());
      System.exit(1);
    }
  }

  private static void printUsage() {
    System.err.println("Usage: OpaqueCli <command> <credentialId> <password> [options]");
    System.err.println();
    System.err.println("Commands:");
    System.err.println("  register   Register a credential with the server");
    System.err.println("  login      Authenticate and print the session key and JWT token");
    System.err.println("  whoami     Register + authenticate + call GET /api/whoami (full round-trip)");
    System.err.println();
    System.err.println("Options:");
    System.err.println("  --server <url>       Server base URL        (default: " + DEFAULT_SERVER + ")");
    System.err.println("  --context <string>   OPAQUE context string  (default: " + DEFAULT_CONTEXT + ")");
    System.err.println("  --memory <kib>       Argon2id memory KiB    (default: " + DEFAULT_MEMORY + ")");
    System.err.println("  --iterations <n>     Argon2id iterations    (default: " + DEFAULT_ITERATIONS + ")");
    System.err.println("  --parallelism <n>    Argon2id parallelism   (default: " + DEFAULT_PARALLELISM + ")");
    System.err.println();
    System.err.println("Examples:");
    System.err.println("  ./gradlew :hofmann-testserver:runOpaqueCli --args=\"register alice@example.com hunter2\" -q");
    System.err.println("  ./gradlew :hofmann-testserver:runOpaqueCli --args=\"login    alice@example.com hunter2\" -q");
    System.err.println("  ./gradlew :hofmann-testserver:runOpaqueCli --args=\"whoami   alice@example.com hunter2\" -q");
  }
}
