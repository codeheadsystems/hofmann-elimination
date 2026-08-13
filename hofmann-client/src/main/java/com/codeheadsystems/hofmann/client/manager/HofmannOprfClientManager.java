package com.codeheadsystems.hofmann.client.manager;

import com.codeheadsystems.hofmann.client.accessor.HofmannOprfAccessor;
import com.codeheadsystems.hofmann.client.config.OprfClientConfig;
import com.codeheadsystems.hofmann.client.model.HofmannHashResult;
import com.codeheadsystems.hofmann.client.model.ServerIdentifier;
import com.codeheadsystems.hofmann.model.oprf.OprfClientConfigResponse;
import com.codeheadsystems.hofmann.model.oprf.OprfRequest;
import com.codeheadsystems.hofmann.model.oprf.OprfResponse;
import com.codeheadsystems.hofmann.model.oprf.PoprfRequest;
import com.codeheadsystems.hofmann.model.oprf.PoprfResponse;
import com.codeheadsystems.hofmann.model.oprf.VoprfRequest;
import com.codeheadsystems.hofmann.model.oprf.VoprfResponse;
import com.codeheadsystems.rfc.oprf.manager.OprfClientManager;
import com.codeheadsystems.rfc.oprf.manager.PoprfClientManager;
import com.codeheadsystems.rfc.oprf.manager.VoprfClientManager;
import com.codeheadsystems.rfc.oprf.manager.VoprfServerManager;
import com.codeheadsystems.rfc.oprf.model.BlindedRequest;
import com.codeheadsystems.rfc.oprf.model.ClientHashingContext;
import com.codeheadsystems.rfc.oprf.model.EvaluatedResponse;
import com.codeheadsystems.rfc.oprf.model.HashResult;
import com.codeheadsystems.rfc.oprf.model.PoprfClientContext;
import com.codeheadsystems.rfc.oprf.model.VoprfClientContext;
import com.codeheadsystems.rfc.oprf.rfc9497.OprfMode;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;
import javax.inject.Inject;
import javax.inject.Singleton;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The type Hofmann oprf client manager.
 */
@Singleton
public class HofmannOprfClientManager {
  private static final Logger log = LoggerFactory.getLogger(HofmannOprfClientManager.class);

  private final HofmannOprfAccessor hofmannOprfAccessor;
  private final Function<ServerIdentifier, OprfClientManager> managerFactory;
  private final Function<ServerIdentifier, VoprfClientManager> voprfManagerFactory;
  private final Function<ServerIdentifier, PoprfClientManager> poprfManagerFactory;

  /**
   * Production constructor — auto-fetches config from each server on first use.
   *
   * <p>Base mode only. The verifiable modes need a server public key pinned per server, which
   * cannot be fetched, so they require the override constructor.
   *
   * @param hofmannOprfAccessor the hofmann oprf accessor
   */
  @Inject
  public HofmannOprfClientManager(final HofmannOprfAccessor hofmannOprfAccessor) {
    this(hofmannOprfAccessor, Collections.emptyMap());
  }

  /**
   * CLI / override constructor — uses the supplied per-server config overrides; falls back to
   * auto-fetching for servers not present in the map.
   *
   * @param hofmannOprfAccessor the hofmann oprf accessor
   * @param overrides           per-server config overrides (may be empty)
   */
  public HofmannOprfClientManager(final HofmannOprfAccessor hofmannOprfAccessor,
                                   final Map<ServerIdentifier, OprfClientConfig> overrides) {
    log.info("HofmannOprfClientManager({}, overrides={})", hofmannOprfAccessor, overrides.size());
    this.hofmannOprfAccessor = hofmannOprfAccessor;
    ConcurrentHashMap<ServerIdentifier, OprfClientManager> cache = new ConcurrentHashMap<>();
    // Memoized separately from the managers. The verifiable factories cross-check the pinned key
    // against this, and re-fetching per mode would let a server answer differently for each.
    ConcurrentHashMap<ServerIdentifier, OprfClientConfigResponse> configCache =
        new ConcurrentHashMap<>();
    this.managerFactory = id -> cache.computeIfAbsent(id, k -> {
      OprfClientConfig cfg = overrides.getOrDefault(k, null);
      if (cfg == null) {
        cfg = OprfClientConfig.fromServerConfig(
            configCache.computeIfAbsent(k, hofmannOprfAccessor::getOprfConfig));
      }
      return new OprfClientManager(cfg.suite());
    });

    ConcurrentHashMap<ServerIdentifier, VoprfClientManager> voprfCache = new ConcurrentHashMap<>();
    this.voprfManagerFactory = id -> voprfCache.computeIfAbsent(id, k -> {
      OprfClientConfig cfg = requirePinned(overrides.get(k), k, OprfMode.VOPRF);
      cfg.assertMatches(configCache.computeIfAbsent(k, hofmannOprfAccessor::getOprfConfig),
          OprfMode.VOPRF);
      return new VoprfClientManager(cfg.voprfSuite(), cfg.pinnedPublicKey(OprfMode.VOPRF));
    });

    ConcurrentHashMap<ServerIdentifier, PoprfClientManager> poprfCache = new ConcurrentHashMap<>();
    this.poprfManagerFactory = id -> poprfCache.computeIfAbsent(id, k -> {
      OprfClientConfig cfg = requirePinned(overrides.get(k), k, OprfMode.POPRF);
      cfg.assertMatches(configCache.computeIfAbsent(k, hofmannOprfAccessor::getOprfConfig),
          OprfMode.POPRF);
      return new PoprfClientManager(cfg.poprfSuite(), cfg.pinnedPublicKey(OprfMode.POPRF));
    });
  }

  /**
   * Package-private test constructor — uses the supplied fixed manager for every server.
   *
   * @param hofmannOprfAccessor the hofmann oprf accessor
   * @param fixedManager        manager returned for every server identifier
   */
  HofmannOprfClientManager(final HofmannOprfAccessor hofmannOprfAccessor,
                            final OprfClientManager fixedManager) {
    log.info("HofmannOprfClientManager({}, fixedManager)", hofmannOprfAccessor);
    this.hofmannOprfAccessor = hofmannOprfAccessor;
    this.managerFactory = ignored -> fixedManager;
    this.voprfManagerFactory = ignored -> {
      throw new IllegalStateException("No VOPRF manager configured for this test instance");
    };
    this.poprfManagerFactory = ignored -> {
      throw new IllegalStateException("No POPRF manager configured for this test instance");
    };
  }

  /**
   * Package-private test constructor — uses the supplied fixed verifiable managers for every
   * server, bypassing config fetch and pinning.
   *
   * @param hofmannOprfAccessor the hofmann oprf accessor
   * @param fixedVoprf          VOPRF manager returned for every server identifier, or null
   * @param fixedPoprf          POPRF manager returned for every server identifier, or null
   */
  HofmannOprfClientManager(final HofmannOprfAccessor hofmannOprfAccessor,
                            final VoprfClientManager fixedVoprf,
                            final PoprfClientManager fixedPoprf) {
    log.info("HofmannOprfClientManager({}, fixedVerifiableManagers)", hofmannOprfAccessor);
    this.hofmannOprfAccessor = hofmannOprfAccessor;
    this.managerFactory = ignored -> {
      throw new IllegalStateException("No base-mode manager configured for this test instance");
    };
    this.voprfManagerFactory = ignored -> fixedVoprf;
    this.poprfManagerFactory = ignored -> fixedPoprf;
  }

  /**
   * Refuses to build a verifiable manager without a pinned key, saying why it cannot simply fetch
   * one.
   */
  private static OprfClientConfig requirePinned(final OprfClientConfig cfg,
                                                final ServerIdentifier id,
                                                final OprfMode mode) {
    if (cfg == null || cfg.pinnedPublicKey(mode) == null) {
      throw new IllegalStateException(
          "No pinned " + mode + " server public key configured for server " + id + ". The "
              + "verifiable modes require a public key authenticated out of band; it cannot be "
              + "fetched from the server, because a proof graded against a key the same server "
              + "supplied proves nothing. Pass an OprfClientConfig override built with "
              + "OprfClientConfig.with" + (mode == OprfMode.VOPRF ? "Voprf" : "Poprf")
              + "ServerPublicKey(hex).");
    }
    return cfg;
  }

  /**
   * Performs the OPRF hashing process using the server as the OPRF provider.
   *
   * <p><strong>This is the entry point to prefer.</strong> {@code sensitiveData} is the client's
   * plaintext OPRF input, and a {@code byte[]} is the only form of it the caller can erase — see
   * {@link #performHash(String, ServerIdentifier)} for what the string form costs. It is copied
   * here, so the caller may clear their own array as soon as this returns; the copy is cleared
   * before this method returns either way.
   *
   * @param sensitiveData    sensitive data to be hashed. The library copies it and clears its own
   *                         copy before returning; your array is untouched and yours to clear
   * @param serverIdentifier the server identifier
   * @return the RFC 9387 compliant OPRF hash of the input, using the server as the OPRF provider.
   */
  public HofmannHashResult performHash(byte[] sensitiveData, ServerIdentifier serverIdentifier) {
    final OprfClientManager clientManager = managerFactory.apply(serverIdentifier);
    // try-with-resources so the context's copy of the input is zeroed on the way out — including
    // when the round trip throws, which is the path where a secret would otherwise be left on the
    // heap with no handle for the caller to clear it by.
    try (ClientHashingContext context = clientManager.hashingContext(sensitiveData)) {
      log.trace("performHashing(requestId={}, serverIdentifier={})", context.requestId(), serverIdentifier);
      final BlindedRequest blindedRequest = clientManager.eliminationRequest(context);
      final OprfRequest oprfRequest = new OprfRequest(blindedRequest);
      final OprfResponse oprfResponse = hofmannOprfAccessor.handleRequest(serverIdentifier, oprfRequest);
      final EvaluatedResponse evaluatedResponse = oprfResponse.evaluatedResponse();
      final HashResult hashResult = clientManager.hashResult(evaluatedResponse, context);
      return new HofmannHashResult(serverIdentifier, hashResult.processIdentifier(), context.requestId(), hashResult.hash());
    }
  }

  /**
   * Convenience overload for callers whose input is already a {@link String}.
   *
   * <p>A {@code String} holding a secret cannot be erased — it is immutable, so the value survives
   * on the heap until the collector reclaims it, and nothing here can change that. Prefer
   * {@link #performHash(byte[], ServerIdentifier)} wherever you control how the secret arrives.
   * See {@code OprfClientManager.hashingContext(String)} for the longer version of the argument.
   *
   * @param sensitiveData    sensitive data to be hashed
   * @param serverIdentifier the server identifier
   * @return the RFC 9387 compliant OPRF hash of the input, using the server as the OPRF provider.
   */
  public HofmannHashResult performHash(String sensitiveData, ServerIdentifier serverIdentifier) {
    if (sensitiveData == null) {
      throw new IllegalArgumentException("Sensitive data is required");
    }
    final byte[] input = sensitiveData.getBytes(StandardCharsets.UTF_8);
    try {
      return performHash(input, serverIdentifier);
    } finally {
      Arrays.fill(input, (byte) 0);
    }
  }

  // ─── VOPRF (RFC 9497 mode 0x01) ────────────────────────────────────────────

  /**
   * Performs a batch of VOPRF evaluations against the server, verifying the DLEQ proof it returns.
   *
   * <p>Batched because one proof covers the whole batch: the server proves once that every
   * evaluation used the key it publicly committed to, and sending elements one at a time would
   * cost a proof each and prove strictly less.
   *
   * <p>The proof is graded against the public key pinned in this client's config for that server,
   * never against anything in the response. If it does not verify, this throws
   * {@link SecurityException} and no output is returned — the point of the mode is that a
   * mis-evaluated result is indistinguishable from a correct one until the proof is checked.
   *
   * <p>The returned list is index-aligned with {@code inputs}. Every element carries the same
   * server, request id and process identifier; only the hash differs. That redundancy is
   * deliberate, so the single-input overload can return exactly what base mode returns.
   *
   * @param inputs           the inputs to evaluate. Copied; the caller may clear its own arrays as
   *                         soon as this returns, and the copies are cleared before it does
   * @param serverIdentifier the server identifier
   * @return one result per input, in order
   * @throws IllegalStateException if no VOPRF public key is pinned for this server
   * @throws SecurityException     if the server's proof does not verify
   */
  public List<HofmannHashResult> performVerifiableHash(final List<byte[]> inputs,
                                                       final ServerIdentifier serverIdentifier) {
    final VoprfClientManager clientManager = voprfManagerFactory.apply(serverIdentifier);
    checkBatchSize(inputs);
    try (VoprfClientContext context = clientManager.hashingContext(inputs)) {
      log.trace("performVerifiableHash(requestId={}, batch={}, serverIdentifier={})",
          context.requestId(), context.size(), serverIdentifier);
      final VoprfRequest request = new VoprfRequest(clientManager.eliminationRequest(context));
      final VoprfResponse response =
          hofmannOprfAccessor.handleVerifiableRequest(serverIdentifier, request);
      final List<HashResult> results =
          clientManager.hashResults(response.evaluatedResponse(), context);
      return toHofmannResults(results, serverIdentifier, context.requestId());
    }
  }

  /**
   * Single-input convenience over {@link #performVerifiableHash(List, ServerIdentifier)}.
   *
   * @param input            the input to evaluate
   * @param serverIdentifier the server identifier
   * @return the result
   */
  public HofmannHashResult performVerifiableHash(final byte[] input,
                                                 final ServerIdentifier serverIdentifier) {
    return performVerifiableHash(List.of(input), serverIdentifier).get(0);
  }

  /**
   * Convenience overload for callers whose input is already a {@link String}.
   *
   * <p>A {@code String} holding a secret cannot be erased; prefer
   * {@link #performVerifiableHash(byte[], ServerIdentifier)}. See
   * {@link #performHash(String, ServerIdentifier)} for the longer version of the argument.
   *
   * @param sensitiveData    the input to evaluate
   * @param serverIdentifier the server identifier
   * @return the result
   */
  public HofmannHashResult performVerifiableHash(final String sensitiveData,
                                                 final ServerIdentifier serverIdentifier) {
    if (sensitiveData == null) {
      throw new IllegalArgumentException("Sensitive data is required");
    }
    final byte[] input = sensitiveData.getBytes(StandardCharsets.UTF_8);
    try {
      return performVerifiableHash(input, serverIdentifier);
    } finally {
      Arrays.fill(input, (byte) 0);
    }
  }

  // ─── POPRF (RFC 9497 mode 0x02) ────────────────────────────────────────────

  /**
   * Performs a batch of POPRF evaluations under a public input, verifying the DLEQ proof.
   *
   * <p>{@code info} travels in the clear and is covered by the proof, which is what distinguishes
   * POPRF from concatenating it onto the private input. An empty array is a valid value meaning
   * "no public input", and is a different public input from any other — so it is required rather
   * than defaulted, and null is rejected.
   *
   * <p>The proof is graded against the tweaked key the client derives from the {@code info} it
   * asked for, not against the server's raw public key. That is what binds the response to the
   * public input requested.
   *
   * @param inputs           the inputs to evaluate, copied and cleared as above
   * @param info             the public input, agreed by both parties. Must not be null
   * @param serverIdentifier the server identifier
   * @return one result per input, in order
   * @throws IllegalStateException if no POPRF public key is pinned for this server
   * @throws SecurityException     if the server's proof does not verify
   */
  public List<HofmannHashResult> performPartiallyObliviousHash(
      final List<byte[]> inputs,
      final byte[] info,
      final ServerIdentifier serverIdentifier) {
    if (info == null) {
      throw new IllegalArgumentException(
          "Public input is required; use an empty array for no public input. An absent public "
              + "input and an empty one are different public inputs producing different outputs.");
    }
    final PoprfClientManager clientManager = poprfManagerFactory.apply(serverIdentifier);
    checkBatchSize(inputs);
    try (PoprfClientContext context = clientManager.hashingContext(inputs, info)) {
      log.trace("performPartiallyObliviousHash(requestId={}, batch={}, serverIdentifier={})",
          context.requestId(), context.size(), serverIdentifier);
      final PoprfRequest request = new PoprfRequest(clientManager.eliminationRequest(context));
      final PoprfResponse response =
          hofmannOprfAccessor.handlePartiallyObliviousRequest(serverIdentifier, request);
      final List<HashResult> results =
          clientManager.hashResults(response.evaluatedResponse(), context);
      return toHofmannResults(results, serverIdentifier, context.requestId());
    }
  }

  /**
   * Single-input convenience over
   * {@link #performPartiallyObliviousHash(List, byte[], ServerIdentifier)}.
   *
   * @param input            the input to evaluate
   * @param info             the public input, must not be null
   * @param serverIdentifier the server identifier
   * @return the result
   */
  public HofmannHashResult performPartiallyObliviousHash(final byte[] input,
                                                         final byte[] info,
                                                         final ServerIdentifier serverIdentifier) {
    return performPartiallyObliviousHash(List.of(input), info, serverIdentifier).get(0);
  }

  /**
   * Convenience overload for callers whose input and public input are already {@link String}s.
   *
   * <p>The {@code String} input carries the erasure problem described on
   * {@link #performHash(String, ServerIdentifier)}. {@code info} does not — it is public by
   * definition — and is encoded as UTF-8.
   *
   * @param sensitiveData    the input to evaluate
   * @param info             the public input, must not be null; empty means no public input
   * @param serverIdentifier the server identifier
   * @return the result
   */
  public HofmannHashResult performPartiallyObliviousHash(final String sensitiveData,
                                                         final String info,
                                                         final ServerIdentifier serverIdentifier) {
    if (sensitiveData == null) {
      throw new IllegalArgumentException("Sensitive data is required");
    }
    if (info == null) {
      throw new IllegalArgumentException("Public input is required; use \"\" for none");
    }
    final byte[] input = sensitiveData.getBytes(StandardCharsets.UTF_8);
    try {
      return performPartiallyObliviousHash(
          input, info.getBytes(StandardCharsets.UTF_8), serverIdentifier);
    } finally {
      Arrays.fill(input, (byte) 0);
    }
  }

  /**
   * Refuses a batch no server could accept, before any curve arithmetic is spent on it. The
   * deployment's own cap may be lower — 64 by default — and that one is enforced server-side as a
   * 400; this only catches the case that is wrong everywhere.
   */
  private static void checkBatchSize(final List<byte[]> inputs) {
    if (inputs == null || inputs.isEmpty()) {
      throw new IllegalArgumentException("At least one input is required");
    }
    if (inputs.size() > VoprfServerManager.ABSOLUTE_MAX_BATCH_SIZE) {
      throw new IllegalArgumentException(
          "Batch of " + inputs.size() + " exceeds the absolute maximum of "
              + VoprfServerManager.ABSOLUTE_MAX_BATCH_SIZE + " that no server configuration raises");
    }
  }

  private static List<HofmannHashResult> toHofmannResults(final List<HashResult> results,
                                                          final ServerIdentifier serverIdentifier,
                                                          final String requestId) {
    return results.stream()
        .map(r -> new HofmannHashResult(
            serverIdentifier, r.processIdentifier(), requestId, r.hash()))
        .toList();
  }

}
