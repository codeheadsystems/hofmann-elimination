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
 *       --args="register|login &lt;credentialId&gt; &lt;password&gt; [options]" -q
 *   ./gradlew :hofmann-testserver:runOpaqueCli \
 *       --args="whoami &lt;jwtToken&gt; [--server &lt;url&gt;]" -q
 *
 * Commands:
 *   register   Register a credential with the server.
 *   login      Authenticate and print the session key and JWT token.
 *   delete     Delete a registration using a JWT token from a prior login.
 *   whoami     Call GET /api/whoami using a JWT token from a prior login.
 *
 * Options (register / login only):
 *   --server &lt;url&gt;       Server base URL          (default: http://localhost:8080)
 *   --context &lt;string&gt;   OPAQUE context string    (default: hofmann-testserver)
 *   --memory &lt;kib&gt;       Argon2id memory in KiB   (default: 65536)
 *   --iterations &lt;n&gt;     Argon2id iterations      (default: 3)
 *   --parallelism &lt;n&gt;    Argon2id parallelism     (default: 1)
 *
 * Typical workflow:
 *   ./gradlew :hofmann-testserver:runOpaqueCli --args="register alice@example.com hunter2" -q
 *   ./gradlew :hofmann-testserver:runOpaqueCli --args="login    alice@example.com hunter2" -q
 *   ./gradlew :hofmann-testserver:runOpaqueCli --args="delete   alice@example.com &lt;token&gt;" -q
 *   ./gradlew :hofmann-testserver:runOpaqueCli --args="whoami   &lt;token-from-login&gt;"       -q
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

    if (positional.isEmpty()) {
      printUsage();
      System.exit(1);
    }

    String command = positional.get(0);

    try {
      switch (command) {
        case "register", "login" -> {
          if (positional.size() < 3) {
            printUsage();
            System.exit(1);
          }
          byte[] credentialId = positional.get(1).getBytes(StandardCharsets.UTF_8);
          byte[] password = positional.get(2).getBytes(StandardCharsets.UTF_8);
          HofmannOpaqueClientManager manager = buildManager(server, context, memory, iterations, parallelism);
          System.out.println("Server  : " + server);
          System.out.println("Context : " + context);
          System.out.println("Argon2id: memory=" + memory + " KiB, iterations=" + iterations
              + ", parallelism=" + parallelism);
          System.out.println();
          if (command.equals("register")) {
            runRegister(manager, credentialId, password);
          } else {
            runLogin(manager, credentialId, password);
          }
        }
        case "delete" -> {
          if (positional.size() < 3) {
            printUsage();
            System.exit(1);
          }
          byte[] credentialId = positional.get(1).getBytes(StandardCharsets.UTF_8);
          String token = positional.get(2);
          HofmannOpaqueClientManager manager = buildManager(server, context, memory, iterations, parallelism);
          System.out.println("Server : " + server);
          System.out.println();
          runDelete(manager, credentialId, token);
        }
        case "whoami" -> {
          if (positional.size() < 2) {
            printUsage();
            System.exit(1);
          }
          String token = positional.get(1);
          System.out.println("Server : " + server);
          System.out.println();
          runWhoami(server, token);
        }
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

  private static HofmannOpaqueClientManager buildManager(String server, String context,
                                                         int memory, int iterations, int parallelism) {
    OpaqueClientConfig config = OpaqueClientConfig.withArgon2id(
        "P256_SHA256", context, memory, iterations, parallelism);
    Map<ServerIdentifier, ServerConnectionInfo> connections = Map.of(
        SERVER_ID, new ServerConnectionInfo(URI.create(server)));
    HofmannOpaqueAccessor accessor = new HofmannOpaqueAccessor(
        HttpClient.newHttpClient(), new ObjectMapper(), connections);
    return new HofmannOpaqueClientManager(config, accessor);
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

  private static void runDelete(HofmannOpaqueClientManager manager,
                               byte[] credentialId, String token) {
    System.out.println("Deleting registration...");
    manager.deleteRegistration(SERVER_ID, credentialId, token);
    System.out.println("Deletion successful.");
  }

  private static void runWhoami(String server, String token)
      throws IOException, InterruptedException {
    System.out.println("Calling GET /api/whoami...");
    HttpRequest request = HttpRequest.newBuilder()
        .uri(URI.create(server + "/api/whoami"))
        .header("Authorization", "Bearer " + token)
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
    System.err.println("Usage:");
    System.err.println("  register <credentialId> <password> [options]");
    System.err.println("  login    <credentialId> <password> [options]");
    System.err.println("  delete   <credentialId> <jwtToken> [--server <url>]");
    System.err.println("  whoami   <jwtToken>                [--server <url>]");
    System.err.println();
    System.err.println("Commands:");
    System.err.println("  register   Register a credential with the server");
    System.err.println("  login      Authenticate and print the session key and JWT token");
    System.err.println("  delete     Delete a registration (requires JWT from a prior login)");
    System.err.println("  whoami     Call GET /api/whoami with a JWT token from a prior login");
    System.err.println();
    System.err.println("Options (register / login):");
    System.err.println("  --server <url>       Server base URL        (default: " + DEFAULT_SERVER + ")");
    System.err.println("  --context <string>   OPAQUE context string  (default: " + DEFAULT_CONTEXT + ")");
    System.err.println("  --memory <kib>       Argon2id memory KiB    (default: " + DEFAULT_MEMORY + ")");
    System.err.println("  --iterations <n>     Argon2id iterations    (default: " + DEFAULT_ITERATIONS + ")");
    System.err.println("  --parallelism <n>    Argon2id parallelism   (default: " + DEFAULT_PARALLELISM + ")");
    System.err.println();
    System.err.println("Workflow:");
    System.err.println("  ./gradlew :hofmann-testserver:runOpaqueCli --args=\"register alice@example.com hunter2\" -q");
    System.err.println("  ./gradlew :hofmann-testserver:runOpaqueCli --args=\"login    alice@example.com hunter2\" -q");
    System.err.println("  # copy the JWT token printed by login, then:");
    System.err.println("  ./gradlew :hofmann-testserver:runOpaqueCli --args=\"whoami   <token>\" -q");
  }
}
