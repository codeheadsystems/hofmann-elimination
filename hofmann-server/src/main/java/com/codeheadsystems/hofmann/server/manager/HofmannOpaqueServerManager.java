package com.codeheadsystems.hofmann.server.manager;

import com.codeheadsystems.hofmann.model.opaque.AuthFinishRequest;
import com.codeheadsystems.hofmann.model.opaque.AuthFinishResponse;
import com.codeheadsystems.hofmann.model.opaque.AuthStartRequest;
import com.codeheadsystems.hofmann.model.opaque.AuthStartResponse;
import com.codeheadsystems.hofmann.model.opaque.RecoveryStartRequest;
import com.codeheadsystems.hofmann.model.opaque.RecoveryVerifyRequest;
import com.codeheadsystems.hofmann.model.opaque.RecoveryVerifyResponse;
import com.codeheadsystems.hofmann.model.opaque.RegistrationDeleteRequest;
import com.codeheadsystems.hofmann.model.opaque.RegistrationFinishRequest;
import com.codeheadsystems.hofmann.model.opaque.RegistrationStartRequest;
import com.codeheadsystems.hofmann.model.opaque.RegistrationStartResponse;
import com.codeheadsystems.hofmann.server.ratelimit.InMemoryRateLimiter;
import com.codeheadsystems.hofmann.server.ratelimit.RateLimitConfigSupplier;
import com.codeheadsystems.hofmann.server.ratelimit.RateLimitExceededException;
import com.codeheadsystems.hofmann.server.ratelimit.RateLimiter;
import com.codeheadsystems.hofmann.server.recovery.RecoveryChallenger;
import com.codeheadsystems.hofmann.server.store.CredentialStore;
import com.codeheadsystems.hofmann.server.store.InMemoryPendingSessionStore;
import com.codeheadsystems.hofmann.server.store.InMemoryRecoveryChallengeStore;
import com.codeheadsystems.hofmann.server.store.InMemoryRecoveryTokenStore;
import com.codeheadsystems.hofmann.server.store.RecoveryChallengeStore;
import com.codeheadsystems.hofmann.server.store.PendingSessionStore;
import com.codeheadsystems.hofmann.server.store.RecoveryTokenStore;
import com.codeheadsystems.hofmann.server.store.VersionedCredential;
import com.codeheadsystems.rfc.opaque.Server;
import com.codeheadsystems.rfc.opaque.model.KE1;
import com.codeheadsystems.rfc.opaque.model.RegistrationRecord;
import com.codeheadsystems.rfc.opaque.model.ServerKE2Result;
import java.util.Arrays;
import java.util.Base64;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Supplier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Framework-agnostic service implementing the OPAQUE-3DH protocol (RFC 9807) server side.
 * <p>
 * Encapsulates all session management and protocol orchestration so that
 * framework-specific adapters ({@code OpaqueResource} for JAX-RS / Dropwizard,
 * {@code OpaqueController} for Spring Boot) can remain thin wrappers that only
 * translate exceptions into framework-specific HTTP error responses.
 * <p>
 * <strong>Key rotation:</strong> accepts a {@code Supplier<OpaqueServerKeyDetail>} to support
 * multiple server key versions. Credentials registered under older key versions are authenticated
 * using the corresponding old keys, and the response includes a {@code keyRotationRequired} flag
 * so clients can re-register under the current keys via the change-password flow.
 * <p>
 * <strong>Exception contract</strong> (callers should map these to HTTP responses):
 * <ul>
 *   <li>{@link IllegalArgumentException}      — bad / missing request data → HTTP 400</li>
 *   <li>{@link SecurityException}             — auth failure or expired session → HTTP 401</li>
 *   <li>{@link UnsupportedOperationException} — recovery not configured → HTTP 404</li>
 *   <li>{@link RateLimitExceededException}    — rate limit or concurrency ceiling → HTTP 429</li>
 *   <li>{@link IllegalStateException}         — session store at capacity → HTTP 503</li>
 * </ul>
 *
 * <p>This list is meant to be exhaustive for the public methods below, and an adapter that maps
 * only what it finds here should be correct. It was not: {@link RateLimitExceededException} is
 * thrown from seven of these methods and was missing from the list, so an adapter written against
 * it returned HTTP 500 under load for a condition the type's own javadoc says to report as 429.
 * If you add a throw, add it here.
 *
 * <p><strong>Two distinct conditions share {@link RateLimitExceededException}</strong>, and
 * operators reading 429 metrics should know they are conflated: a token-bucket budget being
 * exhausted, and a concurrency ceiling being reached ({@link #authStart} and
 * {@link #recoveryVerify} bound how many requests may sit inside their timing floors at once).
 * The second is a capacity signal about this process, not about the caller.
 */
public class HofmannOpaqueServerManager {

  private static final Logger log = LoggerFactory.getLogger(HofmannOpaqueServerManager.class);

  private static final Base64.Encoder B64 = Base64.getEncoder();

  /**
   * Minimum wall-clock time {@link #recoveryVerify} takes, regardless of outcome, so that the
   * latency of the call does not reveal whether the credential exists. See {@link #recoveryVerify}.
   */
  private static final long RECOVERY_VERIFY_MIN_NANOS = 250L * 1_000_000L; // 250 ms

  /**
   * Minimum wall-clock duration of the non-recovery {@code registrationFinish} path.
   * <p>
   * The two branches do different amounts of work: an already-registered credential returns
   * straight after the store lookup, while an unregistered one additionally reads the key
   * detail and performs a write. Against {@link
   * com.codeheadsystems.hofmann.server.store.InMemoryCredentialStore} that difference measures
   * around 340 ns and is unexploitable, but the documented production path is a database-backed
   * {@code CredentialStore}, where the extra work is an INSERT — commonly 0.2–5 ms, which is
   * remotely measurable and would reopen the very enumeration oracle unifying the two responses
   * was meant to close.
   * <p>
   * 25 ms comfortably covers a typical INSERT while staying far below the 250 ms recovery floor,
   * since this runs on every registration rather than only on recovery. Note the floor only
   * masks work that finishes inside it: a store whose writes routinely exceed 25 ms would leak
   * again, which is the same caveat that applies to {@link #RECOVERY_VERIFY_MIN_NANOS}.
   */
  private static final long REGISTRATION_FINISH_MIN_NANOS = 25L * 1_000_000L; // 25 ms

  /**
   * Minimum wall-clock duration of {@link #authStart}, so that the credential store's answer time
   * does not reveal whether the credential exists.
   * <p>
   * {@code Server.generateKE2ForRecordOrFake} equalises the <em>protocol</em> work across the
   * registered and unregistered branches, and it does: against {@link
   * com.codeheadsystems.hofmann.server.store.InMemoryCredentialStore} the two are indistinguishable
   * at AUC 0.5015 over 18,000 interleaved samples. That measurement is also why the residual went
   * unnoticed — the in-memory store answers a hit and a miss in the same few hundred nanoseconds,
   * so it cannot show the thing that actually leaks.
   * <p>
   * The documented production store is JDBC- or Redis-backed, and there a hit and a miss differ by
   * far more than the ~130&micro;s the protocol equalisation closed: an index probe that finds a
   * row returns it, and one that does not returns early. {@link #REGISTRATION_FINISH_MIN_NANOS}
   * puts a write at 0.2–5 ms and this is the same order; neither figure is measured in this repo,
   * so treat both as the reason a floor exists rather than as a result. The protocol work being
   * identical does not help when the lookup in front of it is not.
   * <p>
   * <strong>This is fixed here rather than in the store interface.</strong> The earlier note on
   * this said closing it meant the store answering in constant time and was therefore out of this
   * library's control. That is true of the store and false of the endpoint: a floor at the layer
   * that calls the store absorbs the difference without the store's cooperation, which is exactly
   * what {@link #REGISTRATION_FINISH_MIN_NANOS} already does for the same store on the write path.
   * Requiring every {@code CredentialStore} implementor to build a constant-time database lookup
   * would have been a contract almost none of them could satisfy.
   * <p>
   * 25 ms, matching the registration floor for the same store and the same hazard. The cost is
   * 25 ms added to every login — against an endpoint already behind a rate limiter, already
   * performing several scalar multiplications, and already waiting on a client-side KSF that
   * dwarfs it. That is the trade, stated so it can be disagreed with.
   * <p>
   * <strong>Measured, on the range that motivates it.</strong> Driving {@code authStart} against a
   * store built to answer a hit slower than a miss, 150–200 interleaved samples per branch with the
   * order alternated, three repetitions. At store gaps of 1, 5, 10 and 15 ms the Mann-Whitney AUC
   * lands between 0.47 and 0.58 and the median difference reaching the caller stays within about
   * &plusmn;6&micro;s, with no direction that survives across repetitions. With the floor removed a
   * 3 ms gap gives AUC 1.0000 and separates the branches by 4 ms: a one-probe distinguisher. That
   * range — see {@link #REGISTRATION_FINISH_MIN_NANOS}'s 0.2–5 ms — is what this exists for.
   * <p>
   * <strong>Read the paragraph above as "no signal was detected here", not as "there is no
   * signal", and re-measure before relying on it.</strong> Every figure in this class came from one
   * ordinary shared development machine — an earlier version of this comment described them as
   * coming from two, which was wrong; the spread was run-to-run variance on a single box, not
   * agreement across environments. That machine is not suited to fine timing work: absolute offsets
   * moved by an order of magnitude between runs of the same harness.
   * <p>
   * The bias that introduces runs one way and it is the unhelpful one. Noise widens both
   * distributions, which pulls AUC toward 0.5 — so a noisy environment makes a leak <em>harder</em>
   * to see and makes this constant look better than it may be. The null results above are therefore
   * the weakest claims here, and the one thing worth doing before trusting them is re-running the
   * harness on a quiet host with the governor pinned and the cores isolated. Findings in the other
   * direction — the 3 ms one-probe distinguisher, and the degeneracy on
   * {@link #FLOOR_SETTLE_NANOS} — survive noise, because noise does not manufacture separation.
   * <p>
   * <strong>Two residuals, both toward the edge of the floor, both stated because they were
   * measured rather than reasoned about.</strong>
   * <ul>
   *   <li>At a 20 ms gap the signal is small but no longer clearly noise: AUC 0.37–0.48 across
   *       repetitions, median difference &minus;9 to 0&micro;s, leaning consistently negative.
   *       Distinguishing on that takes a great many probes against a rate-limited endpoint, but it
   *       is not zero and should not be described as zero. Given the measurement caveat above,
   *       treat 20 ms as where the floor starts failing rather than as a precise edge.
   *   <li>Past roughly 22–23 ms the floor stops working, and — see {@link #FLOOR_SETTLE_NANOS} —
   *       in that band it is <em>worse</em> than the single long sleep it replaced. The cause is
   *       that {@code authStart}'s own work — the OPRF evaluation, the masking, the 3DH — is about
   *       2 ms and is spent inside the floor like everything else, so the headroom left for a store
   *       is not the whole 25 ms. Where exactly it crosses depends on how fast the machine runs
   *       that 2 ms, which is why no test pins the boundary.
   * </ul>
   * An overloaded database or a cross-region Redis is the deployment where either matters. Raise
   * this constant there, knowing it raises every login's latency with it.
   * <p>
   * The 31.2&micro;s logging oracle described on {@link #warnOnceAboutMissingKeyVersion} is far
   * inside the floor and no longer measurable through it.
   */
  private static final long AUTH_START_MIN_NANOS = 25L * 1_000_000L; // 25 ms

  /**
   * The single message every recovery-token failure reports.
   * <p>
   * Shared so that "no such token", "token names a different credential" and "another request
   * consumed it first" are indistinguishable to the caller. Distinguishing them confirms to
   * whoever holds a token that it is live and only the identifier is wrong.
   */
  private static final String INVALID_RECOVERY_TOKEN = "Invalid or expired recovery token";

  /**
   * Ceiling on requests simultaneously parked inside {@link #recoveryVerify}'s constant-time
   * floor.
   * <p>
   * The floor holds a request thread for 250 ms, and the per-origin limiter bounds that only per
   * origin: it composes linearly, so a few hundred sources — one IPv6 /64 is far more than that —
   * park enough threads to exhaust a default servlet pool and take the whole application down,
   * not just recovery. This caps the blast radius at a fixed number of threads regardless of how
   * many origins participate. Requests beyond it are rejected immediately rather than queued,
   * because queueing would hold the very resource being protected.
   */
  private static final int MAX_CONCURRENT_RECOVERY_VERIFY = 16;

  private final java.util.concurrent.Semaphore recoveryVerifySlots =
      new java.util.concurrent.Semaphore(MAX_CONCURRENT_RECOVERY_VERIFY);

  /** See {@link #lastCeilingWarnNanos}; same seeding rule, same reason. */
  private final java.util.concurrent.atomic.AtomicLong lastRecoveryCeilingWarnNanos =
      new java.util.concurrent.atomic.AtomicLong(System.nanoTime() - CEILING_WARN_INTERVAL_NANOS);

  /**
   * Ceiling on requests simultaneously parked inside {@link #authStart}'s constant-time floor.
   * <p>
   * A floor that holds a request thread is a thread-exhaustion vector unless the number of threads
   * it can hold is bounded — that is not a hypothesis, it is the finding that was raised against
   * {@link #recoveryVerify} and fixed by {@link #MAX_CONCURRENT_RECOVERY_VERIFY}. Adding a floor
   * here without the matching cap would reintroduce it on the higher-volume endpoint of the two.
   * <p>
   * <strong>128, sized above what the endpoint was measured to serve.</strong> An earlier value of
   * 64 was justified here as "well beyond what the scalar multiplications underneath will support",
   * and that was measured false: without the floor this endpoint sustained 2,500–4,700
   * authentications per second across runs on one 16-core machine, while 64 slots against a 25 ms
   * floor cap it at 2,560/s. The ceiling was at or below the work's own throughput, which made it
   * the binding constraint rather than a backstop. 128 slots give 5,120/s, above every measurement
   * taken, and still inside a default servlet pool with room for other endpoints.
   * <p>
   * <strong>Treat that margin as smaller than it looks.</strong> It is 8% over the fastest run
   * observed, the runs varied by nearly 2x between themselves on the same hardware, and a busy
   * machine <em>understates</em> throughput — so the true figure is likely at the top of that range
   * or above it, and the real margin correspondingly thinner. It is also a fixed number against
   * hardware that keeps getting faster. Expect this to become the binding constraint again, and
   * measure on your own hardware rather than trusting the range above. If throughput matters more
   * to you than the enumeration resistance the floor buys, this constant and
   * {@link #AUTH_START_MIN_NANOS} are the two to move, in that order.
   * <p>
   * <strong>The residual is an availability trade, and it is real.</strong> Enough simultaneous
   * connections to fill this ceiling deny <em>every</em> login for as long as the flood lasts,
   * where before the floor existed they would have degraded it partially. That is deliberate: the
   * alternative to a global ceiling is an unbounded one, and the measured consequence there is the
   * whole application going down rather than one endpoint. Narrowing an outage from "everything" to
   * "login" is the trade being made. The outer defence against reaching it at all is the
   * origin-keyed rate limiter, which is off by default — a deployment exposed to this should turn
   * it on.
   * <p>
   * Refusal here is not itself an enumeration oracle: the ceiling is global, so whether a request
   * is admitted does not depend on the credential it names. It is also charged to no one — see
   * {@link #authStart} on why the ceiling is checked before the rate limiter is consumed.
   */
  private static final int MAX_CONCURRENT_AUTH_START = 128;

  private final java.util.concurrent.Semaphore authStartSlots =
      new java.util.concurrent.Semaphore(MAX_CONCURRENT_AUTH_START);

  /**
   * Rate limiter for the "ceiling reached" warning: at most one line per interval.
   * <p>
   * The warning sits on an unauthenticated endpoint and fires once per refused request, which a
   * reviewer drove to 4,400 WARN lines per second from a single host. That is the same
   * log-amplification vector {@link #warnOnceAboutMissingKeyVersion} exists to close, argued two
   * methods away in this file, and it applies harder here because this is the busier endpoint.
   * Once per interval keeps the operator signal — a ceiling being hit at all is what they need to
   * know — without letting the attacker choose the log volume.
   */
  private static final long CEILING_WARN_INTERVAL_NANOS = 10L * 1_000_000_000L; // 10 s

  /**
   * Seeded a full interval in the past, not {@code Long.MIN_VALUE}.
   *
   * <p>{@code MIN_VALUE} was the obvious sentinel and it silenced the warning permanently:
   * {@code System.nanoTime() - Long.MIN_VALUE} overflows to a negative number, so the interval
   * check never passed and the CAS that advances this was never reached. Measured at 67 million
   * refusals producing zero log lines. Anchoring to {@code nanoTime()} keeps the arithmetic inside
   * the range {@code nanoTime} differences are defined for.
   */
  private final java.util.concurrent.atomic.AtomicLong lastCeilingWarnNanos =
      new java.util.concurrent.atomic.AtomicLong(System.nanoTime() - CEILING_WARN_INTERVAL_NANOS);

  private final Supplier<OpaqueServerKeyDetail> keyDetailSupplier;
  private final CredentialStore credentialStore;
  private final JwtManager jwtManager;
  private final RateLimiter authRateLimiter;
  private final RateLimiter registrationRateLimiter;
  private final PendingSessionStore pendingSessionStore;
  private final RecoveryChallenger recoveryChallenger;
  private final RecoveryTokenStore recoveryTokenStore;
  private final RecoveryChallengeStore recoveryChallengeStore;
  private final RateLimiter recoveryRateLimiter;

  /**
   * Key versions already warned about. Bounded by the number of versions the deployment has used,
   * which is operator-controlled; see {@link #warnOnceAboutMissingKeyVersion}.
   */
  private final java.util.Set<Integer> warnedMissingKeyVersions =
      java.util.concurrent.ConcurrentHashMap.newKeySet();

  /**
   * Instantiates a new Hofmann opaque server manager with default rate limiters
   * and an in-memory pending session store. Recovery is disabled.
   *
   * @param server          the server
   * @param credentialStore the credential store
   * @param jwtManager      the jwt manager
   */
  public HofmannOpaqueServerManager(Server server, CredentialStore credentialStore, JwtManager jwtManager) {
    this(() -> new OpaqueServerKeyDetail(server), credentialStore, jwtManager,
        new InMemoryRateLimiter(new RateLimitConfigSupplier.DefaultRateLimitConfigSupplier().authRateLimitConfig()),
        new InMemoryRateLimiter(new RateLimitConfigSupplier.DefaultRateLimitConfigSupplier().registrationRateLimitConfig()));
  }

  /**
   * Instantiates a new Hofmann opaque server manager with custom rate limiters
   * and a default in-memory pending session store. Recovery is disabled.
   *
   * @param keyDetailSupplier       supplies the current and previous server keys
   * @param credentialStore         the credential store
   * @param jwtManager              the jwt manager
   * @param authRateLimiter         rate limiter for authentication endpoints (keyed by credential)
   * @param registrationRateLimiter rate limiter for registration endpoints (keyed by credential)
   */
  public HofmannOpaqueServerManager(Supplier<OpaqueServerKeyDetail> keyDetailSupplier,
                                    CredentialStore credentialStore, JwtManager jwtManager,
                                    RateLimiter authRateLimiter, RateLimiter registrationRateLimiter) {
    this(keyDetailSupplier, credentialStore, jwtManager, authRateLimiter, registrationRateLimiter,
        new InMemoryPendingSessionStore());
  }

  /**
   * Instantiates a new Hofmann opaque server manager with custom rate limiters
   * and a custom pending session store. Recovery is disabled.
   *
   * @param keyDetailSupplier       supplies the current and previous server keys
   * @param credentialStore         the credential store
   * @param jwtManager              the jwt manager
   * @param authRateLimiter         rate limiter for authentication endpoints (keyed by credential)
   * @param registrationRateLimiter rate limiter for registration endpoints (keyed by credential)
   * @param pendingSessionStore     store for in-flight authentication sessions
   */
  public HofmannOpaqueServerManager(Supplier<OpaqueServerKeyDetail> keyDetailSupplier,
                                    CredentialStore credentialStore, JwtManager jwtManager,
                                    RateLimiter authRateLimiter, RateLimiter registrationRateLimiter,
                                    PendingSessionStore pendingSessionStore) {
    this(keyDetailSupplier, credentialStore, jwtManager, authRateLimiter, registrationRateLimiter,
        pendingSessionStore, null, null, null);
  }

  /**
   * Instantiates a new Hofmann opaque server manager with full configuration including
   * account recovery support.
   * <p>
   * Pass {@code null} for {@code recoveryChallenger} to disable recovery endpoints (they
   * will throw {@link UnsupportedOperationException}).
   *
   * @param keyDetailSupplier       supplies the current and previous server keys
   * @param credentialStore         the credential store
   * @param jwtManager              the jwt manager
   * @param authRateLimiter         rate limiter for authentication endpoints (keyed by credential)
   * @param registrationRateLimiter rate limiter for registration endpoints (keyed by credential)
   * @param pendingSessionStore     store for in-flight authentication sessions
   * @param recoveryChallenger      out-of-band challenge sender/verifier, or null to disable recovery
   * @param recoveryTokenStore      store for recovery tokens, or null (defaults to in-memory if challenger is set)
   * @param recoveryRateLimiter     rate limiter for recovery endpoints, or null (defaults to in-memory if challenger is set)
   */
  public HofmannOpaqueServerManager(Supplier<OpaqueServerKeyDetail> keyDetailSupplier,
                                    CredentialStore credentialStore, JwtManager jwtManager,
                                    RateLimiter authRateLimiter, RateLimiter registrationRateLimiter,
                                    PendingSessionStore pendingSessionStore,
                                    RecoveryChallenger recoveryChallenger,
                                    RecoveryTokenStore recoveryTokenStore,
                                    RateLimiter recoveryRateLimiter) {
    this(keyDetailSupplier, credentialStore, jwtManager, authRateLimiter, registrationRateLimiter,
        pendingSessionStore, recoveryChallenger, recoveryTokenStore, recoveryRateLimiter, null);
  }

  /**
   * Full constructor, including the recovery challenge store.
   *
   * <p>{@code recoveryChallengeStore} records the challenge ids this server issues so that
   * {@code recoveryVerify} can key its limiter on a value the server chose rather than one the
   * caller sent. Null gets the in-memory default, which is single-node.
   *
   * <p><strong>Supply a distributed store in a cluster.</strong> If {@code recoveryStart} and
   * {@code recoveryVerify} land on different nodes with an unshared store, the id is unknown on
   * the verifying node, keying falls back to the credential identifier, and the targeted lockout
   * is live again — with nothing failing to say so. Most production deployments are multi-node,
   * so for most deployments this parameter is the difference between the protection working and
   * quietly not.
   *
   * @param keyDetailSupplier       the OPAQUE server key supplier
   * @param credentialStore         the credential store
   * @param jwtManager              the jwt manager
   * @param authRateLimiter         limiter for authentication
   * @param registrationRateLimiter limiter for registration
   * @param pendingSessionStore     the pending session store
   * @param recoveryChallenger      out-of-band challenge sender/verifier, or null to disable
   * @param recoveryTokenStore      the recovery token store, or null for the in-memory default
   * @param recoveryRateLimiter     limiter for recovery, or null for the default
   * @param recoveryChallengeStore  the recovery challenge store, or null for the in-memory default
   */
  public HofmannOpaqueServerManager(Supplier<OpaqueServerKeyDetail> keyDetailSupplier,
                                    CredentialStore credentialStore,
                                    JwtManager jwtManager,
                                    RateLimiter authRateLimiter,
                                    RateLimiter registrationRateLimiter,
                                    PendingSessionStore pendingSessionStore,
                                    RecoveryChallenger recoveryChallenger,
                                    RecoveryTokenStore recoveryTokenStore,
                                    RateLimiter recoveryRateLimiter,
                                    RecoveryChallengeStore recoveryChallengeStore) {
    this.keyDetailSupplier = keyDetailSupplier;
    this.credentialStore = credentialStore;
    this.jwtManager = jwtManager;
    this.authRateLimiter = authRateLimiter;
    this.registrationRateLimiter = registrationRateLimiter;
    this.pendingSessionStore = pendingSessionStore;
    this.recoveryChallenger = recoveryChallenger;
    if (recoveryChallenger != null) {
      this.recoveryTokenStore = recoveryTokenStore != null
          ? recoveryTokenStore : new InMemoryRecoveryTokenStore();
      // Always present when recovery is enabled. Recording the ids we issue is what lets the
      // verification limiter key on a server-chosen value; without it the key would be whatever
      // the caller sent, which is an unbounded dimension and a guessing budget that resets on
      // demand. The in-memory default is single-node — see the constructor javadoc.
      this.recoveryChallengeStore = recoveryChallengeStore != null
          ? recoveryChallengeStore : new InMemoryRecoveryChallengeStore();
      this.recoveryRateLimiter = recoveryRateLimiter != null
          ? recoveryRateLimiter : new InMemoryRateLimiter(
          new RateLimitConfigSupplier.DefaultRateLimitConfigSupplier().recoveryRateLimitConfig());
    } else {
      this.recoveryTokenStore = null;
      this.recoveryChallengeStore = null;
      this.recoveryRateLimiter = null;
    }
  }

  /**
   * Backward-compatible full constructor that accepts a single {@link Server}.
   *
   * @param server                  the server
   * @param credentialStore         the credential store
   * @param jwtManager              the jwt manager
   * @param authRateLimiter         rate limiter for authentication endpoints (keyed by credential)
   * @param registrationRateLimiter rate limiter for registration endpoints (keyed by credential)
   * @param pendingSessionStore     store for in-flight authentication sessions
   * @param recoveryChallenger      out-of-band challenge sender/verifier, or null to disable recovery
   * @param recoveryTokenStore      store for recovery tokens, or null
   * @param recoveryRateLimiter     rate limiter for recovery endpoints, or null
   */
  public HofmannOpaqueServerManager(Server server, CredentialStore credentialStore, JwtManager jwtManager,
                                    RateLimiter authRateLimiter, RateLimiter registrationRateLimiter,
                                    PendingSessionStore pendingSessionStore,
                                    RecoveryChallenger recoveryChallenger,
                                    RecoveryTokenStore recoveryTokenStore,
                                    RateLimiter recoveryRateLimiter) {
    this(() -> new OpaqueServerKeyDetail(server), credentialStore, jwtManager,
        authRateLimiter, registrationRateLimiter, pendingSessionStore,
        recoveryChallenger, recoveryTokenStore, recoveryRateLimiter);
  }

  /**
   * Shuts down background resources (pending session reaper, session reaper, rate limiters).
   * <p>
   * Should be called on application shutdown to release background threads.
   * In Dropwizard, register this instance as a {@code Managed} component.
   * In Spring Boot, declare the bean with {@code @Bean(destroyMethod = "shutdown")}.
   */
  public void shutdown() {
    pendingSessionStore.shutdown();
    jwtManager.shutdown();
    authRateLimiter.shutdown();
    registrationRateLimiter.shutdown();
    if (recoveryTokenStore != null) {
      recoveryTokenStore.shutdown();
    }
    if (recoveryChallengeStore != null) {
      recoveryChallengeStore.shutdown();
    }
    if (recoveryRateLimiter != null) {
      recoveryRateLimiter.shutdown();
    }
  }

  /**
   * Returns whether account recovery is enabled (a {@link RecoveryChallenger} was provided).
   *
   * @return true if recovery endpoints are available
   */
  public boolean isRecoveryEnabled() {
    return recoveryChallenger != null;
  }

  // ── Registration ─────────────────────────────────────────────────────────

  /**
   * Phase 1 of registration: evaluates the OPRF on the blinded element and returns
   * the evaluated element + server public key.
   *
   * @param req the req
   * @return the registration start response
   * @throws IllegalArgumentException if the request contains missing or invalid fields
   */
  public RegistrationStartResponse registrationStart(RegistrationStartRequest req) {
    return registrationStart(req, null);
  }

  /**
   * Phase 1 of registration with optional recovery token.
   * <p>
   * When a recovery token is present, validates that the token is valid and matches the
   * credential identifier. The token is not consumed here — it will be consumed in
   * {@link #registrationFinish(RegistrationFinishRequest, String)}.
   *
   * @param req         the registration start request
   * @param bearerToken optional recovery token (without "Bearer " prefix), or null for normal registration
   * @return the registration start response
   * @throws IllegalArgumentException    if the request contains missing or invalid fields
   * @throws SecurityException           if the recovery token is invalid, expired, or mismatched
   * @throws RateLimitExceededException  if this credential identifier's registration budget is
   *                                     exhausted
   */
  public RegistrationStartResponse registrationStart(RegistrationStartRequest req, String bearerToken) {
    log.debug("registrationStart()");
    if (!registrationRateLimiter.tryConsume(req.credentialIdentifierBase64())) {
      throw new RateLimitExceededException();
    }
    if (bearerToken != null && !bearerToken.isBlank()) {
      validateRecoveryToken(bearerToken, req.credentialIdentifierBase64());
    }
    Server server = keyDetailSupplier.get().currentServer();
    return new RegistrationStartResponse(
        server.createRegistrationResponse(req.registrationRequest(), req.credentialIdentifier()));
  }

  /**
   * Phase 2 of registration: stores the client's registration record.
   *
   * @param req the req
   * @throws IllegalArgumentException if the request contains missing or invalid fields
   */
  public void registrationFinish(RegistrationFinishRequest req) {
    registrationFinish(req, null);
  }

  /**
   * Phase 2 of registration with optional recovery token.
   * <p>
   * When a recovery token is present, this performs recovery re-registration:
   * the old credential is deleted, all active JWTs are revoked, the recovery
   * token is consumed, and the new registration record is stored.
   *
   * @param req         the registration finish request
   * @param bearerToken optional recovery token (without "Bearer " prefix), or null for normal registration
   * @throws IllegalArgumentException    if the request contains missing or invalid fields
   * @throws SecurityException           if the recovery token is invalid, expired, or mismatched
   * @throws RateLimitExceededException  if the registration budget for this credential identifier
   *                                     is exhausted, or — on the recovery path — the budget keyed
   *                                     on the presented recovery token
   */
  public void registrationFinish(RegistrationFinishRequest req, String bearerToken) {
    log.debug("registrationFinish()");
    if (bearerToken != null && !bearerToken.isBlank()) {
      if (recoveryTokenStore == null) {
        // A recovery token was supplied but recovery is not configured: treat as invalid.
        throw new SecurityException("Invalid or expired recovery token");
      }
      // Rate-limit recovery-token consumption to throttle online token guessing. The token is a
      // single-use bearer credential that authorizes account re-registration; registrationStart is
      // throttled per credential identifier but finish was previously unthrottled, leaving the
      // token-guessing gate wide open. We reuse the recovery rate limiter (keyed by credential
      // identifier, consistent with the rest of the design), so an attacker's guesses against any
      // single account are bounded. Checked before consuming the token so every attempt counts
      // whether or not the token turns out to be valid. Note: a legitimate recovery draws three
      // tokens from this bucket (recoveryStart + recoveryVerify + registrationFinish), which the
      // default capacity (maxTokens=6) accommodates with retry headroom; size the recovery limit
      // accordingly if you tune it.
      // Keyed on the TOKEN, not on the credential identifier, so a junk token presented HERE no
      // longer spends the victim's recovery budget.
      //
      // Scope, because this is narrower than it looks: recoveryStart and recoveryVerify still key
      // on the credential identifier, and both are unauthenticated, so six requests naming a
      // victim still lock them out of those two endpoints for around a minute. That is inherent
      // to rate-limiting an account-scoped operation on behalf of an unauthenticated caller —
      // there is nothing else to key on before a token exists — and the origin limiter bounds how
      // fast one source can do it. Recorded as open in TODO.md rather than described as fixed.
      //
      // Note this key space is attacker-chosen, so the limiter backing it must be one that cannot
      // be exhausted; see the FixedCapacityRateLimiter wiring in both framework integrations.
      if (recoveryRateLimiter != null && !recoveryRateLimiter.tryConsume("token:" + bearerToken)) {
        throw new RateLimitExceededException();
      }
      // Validate the uploaded record here: after the limiter, so the work is throttled, but
      // before remove() consumes the token, so a malformed record does not burn a legitimate
      // recovery attempt, and before the delete below, so it cannot destroy an existing
      // registration.
      validateRecord(req);
      // Recovery-token lifecycle: registrationStart only peeks the token (non-consuming) so the
      // client can safely retry start after a network failure. This finish step is the single
      // consume gate — the account-mutating work below runs at most once per token.
      //
      // Peek, compare, then remove, rather than remove-then-compare. Consuming first meant
      // anyone who observed a token could destroy it by replaying it with a *wrong* identifier:
      // the remove succeeded, the comparison then failed, and the legitimate user had to restart
      // recovery. The identifier check costs nothing and gates the consume.
      //
      // Single-use is still enforced by remove() being atomic, not by the peek: two concurrent
      // finishes both pass the comparison, but only one remove() returns a value and the loser
      // is rejected below. TTL/expiry is re-checked by the store at both steps, so there is no
      // TOCTOU against the peek — a token that expires in between simply fails the remove.
      // One message for every failure here, deliberately. A distinct "does not match credential"
      // told a token holder that the token was live and only the identifier was wrong — an
      // identifier-confirmation oracle. Under the old remove-then-compare they got exactly one
      // such probe before destroying the token; now that a wrong guess is non-destructive they
      // would get a rate-limited stream of them. The limiter above bounds it, but the signal
      // costs nothing to remove. Matters most for deployments whose identifiers are
      // high-entropy rather than email addresses — precisely the ones where the old fail-closed
      // behaviour was doing real work. The distinction is kept at DEBUG for operators.
      String credId = recoveryTokenStore.peek(bearerToken)
          .orElseThrow(() -> new SecurityException(INVALID_RECOVERY_TOKEN));
      if (!credId.equals(req.credentialIdentifierBase64())) {
        log.debug("registrationFinish: recovery token is valid but names a different credential");
        throw new SecurityException(INVALID_RECOVERY_TOKEN);
      }
      if (recoveryTokenStore.remove(bearerToken).isEmpty()) {
        throw new SecurityException(INVALID_RECOVERY_TOKEN);
      }
      // DEBUG, not INFO: the credential identifier is usually an email address, and a
      // re-registration line names an account that just went through recovery. That belongs
      // behind the same switch as the rest of the identifier logging rather than in the
      // default-level record every deployment keeps.
      log.debug("Recovery re-registration for credential {}", req.credentialIdentifierBase64());
      // No delete before the store at the end of this method. delete-then-store left a window in
      // which the credential did not exist, which the unauthenticated registrationFinish path
      // could be flooded to land inside — and a failure between the two steps left the account
      // permanently unregistered with no record to fall back to. store() is contractually an
      // upsert, so replacing in one operation is both narrower and recoverable: on failure the
      // old record survives. Sessions are revoked here, before the new record lands, so no token
      // issued against the old password outlives it.
      jwtManager.revokeByCredentialIdentifier(req.credentialIdentifierBase64());
    } else {
      // Normal (non-recovery) registration. Both branches below must be indistinguishable to an
      // unauthenticated caller, in latency as well as in response, so the whole path runs under
      // a fixed floor — see REGISTRATION_FINISH_MIN_NANOS. The floor deliberately wraps only
      // this branch: the recovery path above is already authenticated by a bearer token and
      // carries its own limiter.
      final long deadlineNanos = System.nanoTime() + REGISTRATION_FINISH_MIN_NANOS;
      try {
        // Consume a token BEFORE looking the credential up:
        // registrationStart is throttled but finish previously was not, so an attacker could
        // probe this endpoint without limit. The check has to precede the existence lookup so
        // that every attempt costs the same whether or not the credential turns out to exist.
        if (!registrationRateLimiter.tryConsume(req.credentialIdentifierBase64())) {
          throw new RateLimitExceededException();
        }
        // Validate after the token is consumed, so the group-element decode — the only
        // expensive part, and up to ~1.2 ms on ristretto255 — cannot be driven unthrottled.
        validateRecord(req);
        // Must not overwrite an existing record: registrationStart/Finish are unauthenticated,
        // so without this guard anyone who knows a victim's credential identifier could
        // re-register it with their own password and take over the account. Existing
        // credentials are updated through the authenticated change-password flow or the
        // recovery flow (which replaces the record above rather than passing through here).
        //
        // One storeIfAbsent rather than loadVersioned-then-store. The two-step form was a
        // check-then-act: two concurrent finishes naming the same identifier could both observe
        // "absent" and both write, so the guard did not actually hold under the very condition
        // an attacker controls — how fast they can call this endpoint. The store is the only
        // layer that can make the check and the write one operation.
        //
        // Return normally either way rather than throwing. Throwing produced HTTP 400 for an
        // existing credential and 204 for a new one, which is an unauthenticated existence
        // oracle — it defeated the enumeration resistance authStart goes to real trouble to
        // provide, where an unknown credential gets a manufactured KE2 precisely so this bit
        // cannot be read. The security property that matters is "does not overwrite", and that
        // is preserved; signalling *why* nothing was written is what leaked. A legitimate client
        // re-running registration therefore sees success without its record being replaced.
        int currentVersion = keyDetailSupplier.get().currentVersion();
        if (!credentialStore.storeIfAbsent(
            req.credentialIdentifier(), req.registrationRecord(), currentVersion)) {
          log.debug("registrationFinish: credential already registered, record left unchanged");
        }
        return;
      } finally {
        sleepUntil(deadlineNanos);
      }
    }
    int currentVersion = keyDetailSupplier.get().currentVersion();
    credentialStore.store(req.credentialIdentifier(), req.registrationRecord(), currentVersion);
  }

  /**
   * Deletes a previously registered credential and immediately revokes all active sessions
   * for that credential.
   * <p>
   * Requires a valid JWT bearer token whose subject (credential identifier) matches the
   * credential being deleted.  This prevents unauthenticated or cross-user deletion.
   * <p>
   * After this method returns, any JWT tokens previously issued for the deleted credential
   * will be rejected by {@link JwtManager#verify}, even if they have not yet expired.
   *
   * @param req         the delete request containing the credential identifier
   * @param bearerToken the JWT bearer token (without "Bearer " prefix)
   * @throws IllegalArgumentException if the request contains missing or invalid fields
   * @throws SecurityException        if the token is missing, invalid, expired, or does not                                  match the credential being deleted
   */
  public void registrationDelete(RegistrationDeleteRequest req, String bearerToken) {
    log.debug("registrationDelete()");
    if (bearerToken == null || bearerToken.isBlank()) {
      throw new SecurityException("Authentication required");
    }
    JwtManager.VerifyResult result = jwtManager.verify(bearerToken)
        .orElseThrow(() -> new SecurityException("Authentication failed"));
    if (!result.subject().equals(req.credentialIdentifierBase64())) {
      throw new SecurityException("Authentication failed");
    }
    credentialStore.delete(req.credentialIdentifier());
    jwtManager.revokeByCredentialIdentifier(req.credentialIdentifierBase64());
  }

  // ── Password Change ──────────────────────────────────────────────────────

  /**
   * Phase 1 of password change: validates the JWT and evaluates the OPRF.
   * Identical to registrationStart() but requires a valid JWT whose subject
   * matches the credential identifier.
   *
   * @param req         the registration start request
   * @param bearerToken the JWT bearer token (without "Bearer " prefix)
   * @return the registration start response
   * @throws SecurityException           if the JWT is missing, invalid, or mismatched
   * @throws IllegalArgumentException    if the request contains missing or invalid fields
   * @throws RateLimitExceededException  if the password-change budget for this credential
   *                                     identifier is exhausted
   */
  public RegistrationStartResponse changePasswordStart(RegistrationStartRequest req, String bearerToken) {
    log.debug("changePasswordStart()");
    if (bearerToken == null || bearerToken.isBlank()) {
      throw new SecurityException("Authentication required");
    }
    JwtManager.VerifyResult result = jwtManager.verify(bearerToken)
        .orElseThrow(() -> new SecurityException("Authentication failed"));
    if (!result.subject().equals(req.credentialIdentifierBase64())) {
      throw new SecurityException("Authentication failed");
    }
    if (!registrationRateLimiter.tryConsume(req.credentialIdentifierBase64())) {
      throw new RateLimitExceededException();
    }
    Server server = keyDetailSupplier.get().currentServer();
    return new RegistrationStartResponse(
        server.createRegistrationResponse(req.registrationRequest(), req.credentialIdentifier()));
  }

  /**
   * Phase 2 of password change: validates the JWT, atomically deletes the old
   * registration record, revokes all sessions, and stores the new record.
   *
   * @param req         the registration finish request
   * @param bearerToken the JWT bearer token (without "Bearer " prefix)
   * @throws SecurityException        if the JWT is missing, invalid, or mismatched
   * @throws IllegalArgumentException if the request contains missing or invalid fields
   */
  public void changePasswordFinish(RegistrationFinishRequest req, String bearerToken) {
    log.debug("changePasswordFinish()");
    if (bearerToken == null || bearerToken.isBlank()) {
      throw new SecurityException("Authentication required");
    }
    JwtManager.VerifyResult result = jwtManager.verify(bearerToken)
        .orElseThrow(() -> new SecurityException("Authentication failed"));
    if (!result.subject().equals(req.credentialIdentifierBase64())) {
      throw new SecurityException("Authentication failed");
    }
    // Third write path to the credential store, and it needs the same guarantee as the other
    // two: the record is still client-supplied, so an unvalidated one is stored and then breaks
    // authentication permanently. Validated after the JWT check (only the account owner reaches
    // here) but before the delete, so a malformed record cannot destroy a working registration
    // and leave the account unregistered.
    validateRecord(req);
    // Revoke first, then replace in a single upsert. The previous delete-then-store pair left a
    // window in which the credential did not exist — reachable by flooding the unauthenticated
    // registrationFinish — and a failure between the two left the account permanently
    // unregistered. See the matching note in the recovery branch of registrationFinish.
    jwtManager.revokeByCredentialIdentifier(req.credentialIdentifierBase64());
    int currentVersion = keyDetailSupplier.get().currentVersion();
    credentialStore.store(req.credentialIdentifier(), req.registrationRecord(), currentVersion);
  }

  /**
   * Validates a client-supplied registration record against the current server's cipher suite.
   * <p>
   * Normalises the failure to {@link IllegalArgumentException} so every write path reports a
   * malformed record as HTTP 400. Without this the status would depend on the suite rather than
   * the fault: BouncyCastle rejects a bad compressed point with {@code IllegalArgumentException}
   * on the NIST curves, while ristretto255 raises {@link SecurityException} — which the adapters
   * map to 401, an authentication challenge for an unauthenticated endpoint where the caller has
   * no credentials to correct.
   */
  private void validateRecord(final RegistrationFinishRequest req) {
    try {
      keyDetailSupplier.get().currentServer().validateRegistrationRecord(req.registrationRecord());
    } catch (SecurityException e) {
      throw new IllegalArgumentException("Invalid registration record", e);
    }
  }

  // ── Recovery ───────────────────────────────────────────────────────────

  /**
   * Initiates account recovery by sending an out-of-band challenge.
   * <p>
   * Always returns successfully to prevent user enumeration — the
   * {@link RecoveryChallenger} is responsible for not revealing whether
   * the credential exists.
   *
   * @param req the recovery start request
   * @throws UnsupportedOperationException if recovery is not configured
   * @throws IllegalArgumentException      if the request contains missing or invalid fields
   * @throws RateLimitExceededException    if the recovery budget for this credential identifier is
   *                                       exhausted. Note this is thrown on a key that does not
   *                                       depend on whether the account exists, so it is not itself
   *                                       an enumeration signal
   */
  public void recoveryStart(RecoveryStartRequest req) {
    log.debug("recoveryStart()");
    if (recoveryChallenger == null) {
      throw new UnsupportedOperationException("Account recovery is not configured");
    }
    // Still keyed on the credential identifier, and that is inherent here rather than an
    // oversight: before a challenge exists there is nothing to key on that an attacker cannot
    // also supply. What the challenge id changes is recoveryVerify — see below — so a flood here
    // can cost a victim a new challenge but no longer costs them the ability to complete one.
    if (!recoveryRateLimiter.tryConsume("start:" + req.credentialIdentifierBase64())) {
      throw new RateLimitExceededException();
    }
    // Generated unconditionally, even for a challenger that ignores it, so the value never
    // depends on anything the caller sent and the two paths cost the same.
    String challengeId = UUID.randomUUID().toString();
    // Recorded before it is sent. If the challenger throws mid-send the entry is harmless — it
    // expires on its TTL and authorises nothing — whereas sending first and recording second
    // could deliver an id the server does not recognise, silently costing the user the protection.
    recoveryChallengeStore.store(challengeId, req.credentialIdentifierBase64());
    recoveryChallenger.sendChallenge(req.credentialIdentifier(), challengeId);
  }

  /**
   * Verifies the challenge response and issues a single-use recovery token.
   *
   * @param req the recovery verify request
   * @return the recovery verify response containing the recovery token
   * @throws UnsupportedOperationException if recovery is not configured
   * @throws IllegalArgumentException      if the request contains missing or invalid fields
   * @throws SecurityException             if the challenge response is incorrect or expired
   * @throws RateLimitExceededException    if the recovery budget is exhausted, or if
   *                                       16 requests are already inside the timing floor — the
   *                                       second is a capacity signal about this process, not about
   *                                       the caller
   */
  public RecoveryVerifyResponse recoveryVerify(RecoveryVerifyRequest req) {
    log.debug("recoveryVerify()");
    if (recoveryChallenger == null) {
      throw new UnsupportedOperationException("Account recovery is not configured");
    }
    // Throttle every verification attempt (not just recoveryStart). Without this the OOB
    // challenge code can be brute-forced at request rate, and the unconditional 250ms floor
    // below turns each unthrottled call into a thread-exhaustion DoS. Rate-limit rejection
    // depends only on the key below, not on whether the account exists, so it is not itself an
    // enumeration oracle either way.
    //
    // Keyed on the challenge id when the challenger delivers one out of band. That is what closes
    // the targeted lockout: the id reaches the account owner's mailbox and nowhere else, so an
    // attacker naming a victim spends their own budget rather than the victim's, and spending the
    // victim's costs them a 122-bit guess. Keying on the credential identifier — which the caller
    // supplies and an attacker knows — is what made six unauthenticated requests enough to lock
    // someone out of their own recovery.
    //
    // Falls back to identifier keying for a challenger that has not opted in, because there is
    // then no id to key on: the residual is real for those deployments and documented on
    // RecoveryChallenger.
    final ChallengeBinding binding = recoveryVerifyBinding(req);
    if (!recoveryRateLimiter.tryConsume(binding.rateLimitKey())) {
      throw new RateLimitExceededException();
    }
    // Enforce a constant-time floor over the whole verification. A RecoveryChallenger may
    // short-circuit (return false instantly) for an unknown credential while doing real
    // comparison work for a known one. Without this floor that latency difference is a
    // user-enumeration oracle that defeats OPAQUE's enumeration resistance: recoveryStart
    // always returns 202, but an attacker could distinguish existing from non-existing
    // accounts by timing recoveryVerify. The floor (applied to both the success and the
    // failure path) bounds the observable timing to its jitter. Implementations should still
    // use constant-time comparison; if a challenger's verification can exceed the floor for
    // existing accounts, raise RECOVERY_VERIFY_MIN_NANOS accordingly.
    // Refuse rather than queue when too many requests are already inside the floor: queueing
    // would consume the request threads this exists to protect.
    if (!recoveryVerifySlots.tryAcquire()) {
      // Rate-limited for the same reason as authStart's: an unauthenticated caller must not choose
      // the log volume. Lower traffic here, but the argument does not depend on traffic.
      if (shouldWarn(lastRecoveryCeilingWarnNanos)) {
        log.warn("recoveryVerify at its concurrency ceiling ({}); rejecting, and logging this at "
            + "most once every {}s. Sustained occurrences indicate an attempt to exhaust request "
            + "threads via the constant-time floor.",
            MAX_CONCURRENT_RECOVERY_VERIFY, CEILING_WARN_INTERVAL_NANOS / 1_000_000_000L);
      }
      throw new RateLimitExceededException();
    }
    final long deadlineNanos = System.nanoTime() + RECOVERY_VERIFY_MIN_NANOS;
    try {
      // Refused inside the floor and with the same failure as a wrong code, so a mismatched id is
      // not distinguishable from an incorrect response. Metered first, above, so this is not a
      // free unmetered path.
      if (binding.mismatched()) {
        log.debug("recoveryVerify: challenge id was issued for a different credential");
        throw new SecurityException("Recovery verification failed");
      }
      if (!recoveryChallenger.verifyResponse(
          req.credentialIdentifier(), req.challengeId(), req.challengeResponse())) {
        throw new SecurityException("Recovery verification failed");
      }
      String token = UUID.randomUUID().toString();
      recoveryTokenStore.store(token, req.credentialIdentifierBase64());
      return new RecoveryVerifyResponse(token);
    } finally {
      try {
        sleepUntil(deadlineNanos);
      } finally {
        recoveryVerifySlots.release();
      }
    }
  }

  /**
   * Length of the identical settling phase every floor ends with, and the size of its steps.
   *
   * <p><strong>This is not an implementation detail; it is the difference between the floor
   * working and the floor leaking.</strong> {@code Thread.sleep} does not exit exactly on time, and
   * how late it exits depends on how it got there — on the length of the sleep, and on what the
   * thread was doing beforehand. A floor sleeps for whatever the branch <em>left over</em>, so the
   * slow branch sleeps less, and that difference in exit behaviour carries the branch straight
   * through the floor built to hide it.
   *
   * <p>Two wrong answers were measured before this one, on a harness that reproduces the shape of
   * {@code authStart} — block for the store gap, burn ~2 ms of work, floor to 25 ms — with the
   * strategies and both branches fully interleaved so they see identical machine conditions.
   * <p>
   * Interleaving is not decoration here. Every measurement in this class was taken on one shared
   * development machine that is poor at fine timing — see {@link #AUTH_START_MIN_NANOS} — so the
   * absolute microsecond figures below move by an order of magnitude between runs and are worth
   * nothing on their own. Flipping the strategies and the branches sample by sample is what makes
   * the <em>comparison</em> survive that, and the comparison is all the choice below rests on. The
   * first attempt at this fix was measured without interleaving, reported no signal, and was wrong.
   * 250 samples per branch, three repetitions:
   *
   * <ul>
   *   <li><strong>One long sleep</strong> (the original): AUC 0.34–0.53, median difference
   *       &minus;144 to +39&micro;s between runs, direction not stable. A leak, but a noisy one —
   *       the variance is wide enough to bury the offset.
   *   <li><strong>Uniform 1 ms slices</strong> (the first attempt at a fix): AUC 0.48–0.74, median
   *       difference stably <em>positive</em> and growing with the store gap. Worse than doing
   *       nothing — not because the offset is larger in microseconds, which it is not, but because
   *       it is consistent, and a consistent small offset is a distinguisher where a noisy larger
   *       one is not. The final slice is the same length on both branches, which is what that
   *       attempt reasoned about; the <em>number</em> of slices is not — 13 against 23 at a 10 ms
   *       gap — and a thread that has just taken 23 consecutive timer wakeups is in a measurably
   *       different state from one that took 13.
   *   <li><strong>A fixed settling phase</strong> (this): AUC 0.42–0.55, median difference within
   *       a few microseconds, direction not stable. One coarse sleep to
   *       {@code deadline - FLOOR_SETTLE_NANOS}, then steps of {@code FLOOR_SETTLE_STEP_NANOS} —
   *       the same shape on every branch. Better than the single sleep at every store gap from 1
   *       to 21 ms, on three independent harnesses.
   * </ul>
   *
   * <p><strong>The degeneracy, which is structural rather than statistical.</strong> "The same
   * shape on every branch" holds only while the branch has more than {@code FLOOR_SETTLE_NANOS}
   * left to burn. Past that {@code coarse} is non-positive, the coarse sleep is skipped, and the
   * step count goes branch-dependent again — around nine steps against twenty — which is precisely
   * the property this exists to remove. That much is readable in {@link #sleepUntil} and needs no
   * measurement to establish.
   * <p>
   * Measured, it shows up at a 22 ms store gap under this 25 ms floor as AUC 0.82–0.84, against
   * 0.47 for the single long sleep. Take the first number seriously and the comparison lightly: a
   * noisy environment suppresses AUC toward 0.5, so a detected 0.82 is real and possibly
   * understated, whereas 0.47 for the comparator is a null result on hardware unsuited to
   * measuring it — and the same harness put that comparator at AUC 0.35 one millisecond away, at
   * 21 ms. So "this strategy leaks badly in that band" is established; "it is worse there than what
   * it replaced" is one measurement against an erratic baseline and is not.
   * <p>
   * Either way the band sits inside the region {@link #AUTH_START_MIN_NANOS} already declares
   * broken — past ~22 ms the floor does not work — so the remedy is the same one stated there,
   * raise the floor. It is recorded because nothing in the build notices, and tracked in TODO.md.
   *
   * <p>The cost is about ten timer wakeups per floored request rather than one (measured: min 4,
   * median 10, max 14), and it does not scale with the floor: {@link #RECOVERY_VERIFY_MIN_NANOS}'s
   * 250 ms floor pays the same median of 10 or 11, where uniform slicing would have paid 250.
   */
  private static final long FLOOR_SETTLE_NANOS = 2_000_000L; // 2 ms

  /** Step size within the settling phase. See {@link #FLOOR_SETTLE_NANOS}. */
  private static final long FLOOR_SETTLE_STEP_NANOS = 100_000L; // 100 us

  /**
   * Busy-free wait until {@code deadlineNanos} (from {@link System#nanoTime()}) has passed.
   *
   * <p>One coarse sleep, then a settling phase of fixed shape, so that the wait's own exit
   * behaviour does not depend on how long it waited. See {@link #FLOOR_SETTLE_NANOS} — the shape
   * is load-bearing and was measured, not guessed.
   */
  private static void sleepUntil(final long deadlineNanos) {
    long coarse = deadlineNanos - FLOOR_SETTLE_NANOS - System.nanoTime();
    if (coarse > 0 && !sleepNanos(coarse)) {
      return;
    }
    long remaining = deadlineNanos - System.nanoTime();
    while (remaining > 0) {
      if (!sleepNanos(Math.min(remaining, FLOOR_SETTLE_STEP_NANOS))) {
        return;
      }
      remaining = deadlineNanos - System.nanoTime();
    }
  }

  /** Sleeps the given nanoseconds; returns false if interrupted, with the flag restored. */
  private static boolean sleepNanos(final long nanos) {
    try {
      Thread.sleep(nanos / 1_000_000L, (int) (nanos % 1_000_000L));
      return true;
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      return false;
    }
  }

  /**
   * Resolves a presented challenge id: which bucket to charge, and whether to refuse the request.
   *
   * <p>The id keys the limiter only when this server issued it <em>for the credential the request
   * names</em>. Anything else — absent, unknown, expired, or issued for someone else — charges the
   * credential identifier, which is the pre-existing behaviour and costs a legitimate user
   * nothing: they always present an id issued for their own credential, so they are on a
   * different bucket from anyone attacking them.
   */
  private ChallengeBinding recoveryVerifyBinding(final RecoveryVerifyRequest req) {
    String challengeId = req.challengeId();
    String identifier = req.credentialIdentifierBase64();
    if (challengeId == null || challengeId.isBlank()) {
      return new ChallengeBinding("verify:" + identifier, false);
    }
    // Only an id this server issued *for this credential* may key the limiter. A fabricated one
    // would otherwise give every guess a fresh bucket, and let a caller mint unbounded distinct
    // keys; checking it here is why the store exists.
    String issuedFor = recoveryChallengeStore.peek(challengeId).orElse(null);
    if (identifier.equals(issuedFor)) {
      return new ChallengeBinding("challenge:" + challengeId, false);
    }
    if (issuedFor != null) {
      // A genuine id, issued for a *different* credential. This previously keyed on the id — "it
      // belongs to whoever holds it, let them spend their own budget" — which inverted what is
      // being metered. The thing being metered is a guess against the *named* credential's
      // challenge, so the budget has to attach to the credential under attack, not to a token the
      // caller happens to hold. Otherwise anyone can recover their own account, obtain a real id,
      // and then meter guesses against a victim on a bucket they own and can refresh at will —
      // the attacker-chosen limiter key this store exists to prevent, laundered through a real id.
      //
      // It is also rejected outright below rather than merely metered differently: an id issued
      // for another credential is an incoherent request, and letting it reach verifyResponse is
      // what turned the mis-keying into a guessing oracle against the victim's code.
      return new ChallengeBinding("verify:" + identifier, true);
    }
    log.debug("recoveryVerify: presented challenge id is unknown or expired; "
        + "falling back to identifier keying for this request");
    return new ChallengeBinding("verify:" + identifier, false);
  }

  /**
   * How a presented challenge id resolved: which bucket to charge, and whether the request is
   * incoherent and must be refused.
   *
   * <p>One computation rather than two so the key and the verdict cannot disagree — which is
   * exactly how the earlier version went wrong, selecting a key without gating anything.
   */
  private record ChallengeBinding(String rateLimitKey, boolean mismatched) {
  }

  private void validateRecoveryToken(String token, String expectedCredentialIdentifierBase64) {
    if (recoveryTokenStore == null) {
      throw new SecurityException(INVALID_RECOVERY_TOKEN);
    }
    // Intentionally non-consuming (peek): registrationStart performs no persistent state change
    // (it only returns a registration response), so a token may validate multiple start calls
    // within its TTL. This keeps start idempotent and retryable if the client loses the response.
    // Single use is enforced by the atomic remove() in registrationFinish, which is the only step
    // that mutates account state. See registrationFinish for the full lifecycle.
    String credId = recoveryTokenStore.peek(token)
        .orElseThrow(() -> new SecurityException(INVALID_RECOVERY_TOKEN));
    if (!credId.equals(expectedCredentialIdentifierBase64)) {
      // Same single message as registrationFinish, and it matters more here. This path is
      // non-consuming by design, so a distinct "does not match credential" was a *freely
      // repeatable* identifier-confirmation oracle for anyone holding a token — no token is
      // spent to ask, and unlike the finish path there is no token-keyed limiter in front of it
      // (registrationStart's limiter keys on the credential identifier, which is the very thing
      // being guessed, so each guess draws from a different bucket).
      log.debug("registrationStart: recovery token is valid but names a different credential");
      throw new SecurityException(INVALID_RECOVERY_TOKEN);
    }
  }

  // ── Authentication ────────────────────────────────────────────────────────

  /**
   * AKE phase 1: generates KE2 and returns it with a session token.
   * When the credential identifier is unknown, a fake KE2 is returned to prevent
   * user enumeration (RFC 9807 §10.6).
   *
   * <p>Enumeration resistance here is three things, not one, and the response body is only the
   * first. The manufactured KE2 makes the <em>content</em> identical; {@code
   * Server.generateKE2ForRecordOrFake} makes the <em>protocol work</em> identical; and the floor
   * below absorbs the <em>credential store lookup</em>, which is what dominates on any store that
   * is not in-memory. All three are needed — each of the first two was, at the time it landed,
   * believed to have finished the job. The floor's own limits are stated on
   * {@link #AUTH_START_MIN_NANOS} and are not small print: it absorbs a store gap cleanly up to
   * around 15 ms, leaks a couple of microseconds by 20 ms, and stops working entirely past roughly
   * 22–23 ms.
   *
   * <p>One thing sits outside the floor: a credential identifier that is not valid base64 is
   * rejected by the request decode in about 0.06 ms rather than 25 ms. That is not an existence
   * oracle — it depends on the bytes the caller sent and not on whether any account exists — but a
   * caller can tell a malformed request from a well-formed one by timing, which is information they
   * already have.
   *
   * @param req the req
   * @return the auth start response
   * @throws IllegalArgumentException                                              if the request
   *                                                                               contains missing
   *                                                                               or invalid fields
   * @throws IllegalStateException                                                 if the session
   *                                                                               store has reached
   *                                                                               capacity
   * @throws com.codeheadsystems.hofmann.server.ratelimit.RateLimitExceededException
   *     if the credential's rate limit is exhausted, or if 128 requests are already inside the
   *     floor
   */
  public AuthStartResponse authStart(AuthStartRequest req) {
    log.debug("authStart()");
    // The ceiling is checked BEFORE the rate limiter is consumed, and the order matters.
    //
    // Metering first reads better — "do not let a request that will be refused anyway occupy a
    // slot" — and it is wrong. The slot is held for microseconds on that path, whereas a token
    // spent on a request the ceiling then refuses is gone for up to a minute: a reviewer flooded
    // the ceiling and measured a legitimate user refused 10/10 during the flood and still refused
    // 5/5 after it stopped, her whole burst drained by refusals that had nothing to do with her.
    // That turns a transient denial into a lasting one for exactly the users being protected.
    // Charging nothing for a refusal the server chose to make is the correct side of the trade.
    if (!authStartSlots.tryAcquire()) {
      warnCeilingReached();
      throw new RateLimitExceededException();
    }
    try {
      if (!authRateLimiter.tryConsume(req.credentialIdentifierBase64())) {
        throw new RateLimitExceededException();
      }
      // The floor starts before the store lookup and ends after the response is built, because the
      // lookup is the thing being masked. Deliberately not started until the limiter has passed:
      // rate-limit rejection does not depend on whether the credential exists, so there is nothing
      // to hide, and parking a refused request for 25 ms would hold a slot for no reason.
      final long deadlineNanos = System.nanoTime() + AUTH_START_MIN_NANOS;
      try {
        return authStartWithinFloor(req);
      } finally {
        sleepUntil(deadlineNanos);
      }
    } finally {
      authStartSlots.release();
    }
  }

  /** At most one ceiling warning per {@link #CEILING_WARN_INTERVAL_NANOS}; see that constant. */
  private void warnCeilingReached() {
    if (shouldWarn(lastCeilingWarnNanos)) {
      log.warn("authStart at its concurrency ceiling ({}); rejecting, and logging this at most "
          + "once every {}s. Sustained occurrences indicate either genuine load beyond what the "
          + "floor admits or an attempt to exhaust request threads through it.",
          MAX_CONCURRENT_AUTH_START, CEILING_WARN_INTERVAL_NANOS / 1_000_000_000L);
    }
  }

  /**
   * True at most once per {@link #CEILING_WARN_INTERVAL_NANOS} for the given clock.
   *
   * <p>The CAS is what makes it "at most once" rather than "about once": two threads reading the
   * same value cannot both win it, so a thousand simultaneous refusals produce one line.
   */
  private static boolean shouldWarn(final java.util.concurrent.atomic.AtomicLong lastWarnNanos) {
    long now = System.nanoTime();
    long last = lastWarnNanos.get();
    return now - last >= CEILING_WARN_INTERVAL_NANOS
        && lastWarnNanos.compareAndSet(last, now);
  }

  /**
   * The body of {@link #authStart}, run inside its constant-time floor.
   *
   * <p>Split out so the floor's {@code try/finally} does not indent the protocol logic, and so
   * that every {@code return} and every throw inside it is covered by the floor by construction
   * rather than by remembering to wrap one. Nothing here may be moved outside that region: the
   * whole point is that an observer cannot tell the branches apart, and work done after the floor
   * is released is work whose duration is visible.
   */
  private AuthStartResponse authStartWithinFloor(AuthStartRequest req) {
    byte[] credentialIdentifier = req.credentialIdentifier();
    KE1 ke1 = req.ke1();

    OpaqueServerKeyDetail keyDetail = keyDetailSupplier.get();
    Optional<VersionedCredential> versioned = credentialStore.loadVersioned(credentialIdentifier);

    // All three cases converge on one call so that the registered and unregistered paths execute
    // the same code doing the same work. Previously the two fake branches called
    // generateFakeKE2 and the registered branch called generateKE2, and the fake record's two
    // HKDF expansions plus scalar multiplication made the unregistered path measurably slower —
    // 743.7µs against 872.7µs, a 17.4% offset in a fixed direction. That is a user-enumeration
    // oracle regardless of how indistinguishable the response body is, and it is the residual
    // that remained once the free oracles were closed.
    Server server;
    RegistrationRecord record;
    int keyVersion;
    // Resolved once and held. The guard used to be a separate invocation from the value —
    // `serverForVersion(...) != null` in the condition, `serverForVersion(...)` again in the body —
    // so a supplier handing out a mutable previousServers map could satisfy the guard and then
    // return null, producing an NPE below instead of the fake-KE2 fallback. OpaqueServerKeyDetail
    // is a record that does not defensively copy that map, and the supplier interface exists to
    // let a deployment manage keys dynamically, so it is invited rather than merely possible.
    // Both in-repo suppliers use immutable maps, which is why this was latent.
    Server versionedServer = versioned
        .map(vc -> keyDetail.serverForVersion(vc.keyVersion()))
        .orElse(null);
    if (versionedServer != null) {
      VersionedCredential vc = versioned.get();
      keyVersion = vc.keyVersion();
      server = versionedServer;
      record = vc.record();
    } else {
      versioned.ifPresent(vc -> warnOnceAboutMissingKeyVersion(vc.keyVersion()));
      // A null record means "answer with a fake". Both the unregistered case and the credential
      // that exists but cannot be authenticated under any known key version take this path, so
      // neither is distinguishable from the other or from a real one — subject to the logging
      // caveat on warnOnceAboutMissingKeyVersion, which is why that method exists.
      keyVersion = keyDetail.currentVersion();
      server = keyDetail.currentServer();
      record = null;
    }
    ServerKE2Result ke2Result =
        server.generateKE2ForRecordOrFake(null, record, credentialIdentifier, ke1, null);

    String sessionToken = UUID.randomUUID().toString();
    // NOTE: keep this method's remaining work identical across branches, and keep all of it inside
    // the floor. The floor now absorbs a per-branch difference that finishes within it — which the
    // 31.2µs log statement described on warnOnceAboutMissingKeyVersion does — but "the floor will
    // cover it" is not a licence to add branch-dependent work, because nothing here notices when a
    // branch grows past 25 ms.
    pendingSessionStore.store(sessionToken, ke2Result.serverAuthState(),
        req.credentialIdentifierBase64(), keyVersion);

    return new AuthStartResponse(sessionToken, ke2Result.ke2());
  }

  /**
   * Warns at most once per key version that a credential is stranded on a key that is gone.
   *
   * <p><strong>Once, because logging on one branch of three is a timing oracle.</strong> The
   * warning used to run per request, inside the region an attacker times. A reviewer measured it
   * against logback at INFO with a file appender — an ordinary production configuration, not a
   * contrived one — and the stranded branch was 31.2&micro;s slower than the unregistered branch:
   * AUC 0.64, about 1,400 probes per identifier to distinguish at 5&sigma;. The minimum shifted too,
   * so it was a floor shift rather than a tail artefact.
   *
   * <p>That is seven times <em>dearer</em> than the 200-probe oracle
   * {@code generateKE2ForRecordOrFake} was written to close — this text said "cheaper", which
   * inverts 1,400 against 200 and overstated the case it was making. It is still an oracle worth
   * closing, and it distinguishes exactly the population that work claimed to cover:
   * "this account exists but is stranded on a dropped key version" against "this account does not
   * exist". It reads as no signal on a bare test classpath, where the logger is a NOP and the call
   * costs 1.5&micro;s — which is why it survived the change that was supposed to fix this branch,
   * and why the commit that made it asserted a property it had not measured.
   *
   * <p>A stranded key version is a deployment condition, not a per-request one: the operator needs
   * to know it happened, not how many times. Logging once per version means an attacker sees the
   * cost on at most one probe ever, and it also closes the log-amplification vector — before this,
   * anyone who knew one stranded identifier could drive unbounded WARN-level output at an
   * unauthenticated endpoint.
   *
   * <p>The set is bounded by the number of distinct key versions the deployment has ever used,
   * which is small and operator-controlled rather than attacker-controlled. That is the property
   * that makes an unbounded-looking set safe here; it would not be safe keyed on the credential
   * identifier.
   *
   * <p><strong>The timing half of this is now also covered by {@link #AUTH_START_MIN_NANOS}</strong>
   * — 31.2&micro;s finishes well inside a 25 ms floor, so a per-request warning would no longer be
   * measurable from outside. Once-per-version stays anyway, for the second reason above: it closes
   * the log-amplification vector, where anyone knowing one stranded identifier could drive
   * unbounded WARN output from an unauthenticated endpoint. Two independent reasons, and only one
   * of them has been superseded.
   *
   * @param keyVersion the version that has no server
   */
  private void warnOnceAboutMissingKeyVersion(int keyVersion) {
    if (warnedMissingKeyVersions.add(keyVersion)) {
      log.warn("No server key for version {} — credentials registered under it cannot be "
          + "authenticated and will receive a fake KE2. This is logged once per version: the "
          + "warning sits on one branch of authStart, and emitting it per request makes that "
          + "branch measurably slower than the others.", keyVersion);
    }
  }

  /**
   * AKE phase 2: verifies the client MAC and returns the session key.
   * <p>
   * When the credential was authenticated with an older server key version,
   * the response includes {@code keyRotationRequired=true} so the client
   * can re-register via the change-password flow.
   *
   * @param req the req
   * @return the auth finish response
   * @throws IllegalArgumentException if the request contains missing or invalid fields
   * @throws SecurityException        if the session token is unknown / expired, or if                                  the client MAC does not verify
   */
  public AuthFinishResponse authFinish(AuthFinishRequest req) {
    // The session token is a bearer credential for the pending handshake, so it is not logged —
    // same policy InMemoryRecoveryTokenStore states for the structurally equivalent recovery
    // token. Logging it at DEBUG put it in any deployment running debug logging.
    log.debug("authFinish()");
    PendingSessionStore.PendingSession pending = pendingSessionStore.remove(req.sessionToken())
        .orElseThrow(() -> new SecurityException("Session not found or expired"));

    OpaqueServerKeyDetail keyDetail = keyDetailSupplier.get();
    Server server = keyDetail.serverForVersion(pending.keyVersion());
    if (server == null) {
      server = keyDetail.currentServer();
    }
    byte[] sessionKey = server.serverFinish(pending.state(), req.ke3());
    try {
      String sessionKeyBase64 = B64.encodeToString(sessionKey);
      // The key is not passed to the JWT layer any more: nothing ever read it back out of the
      // session store, and a String cannot be zeroed. See SessionData.
      String token = jwtManager.issueToken(pending.credentialIdentifierBase64());

      Boolean rotationRequired =
          pending.keyVersion() < keyDetail.currentVersion() ? Boolean.TRUE : null;
      return new AuthFinishResponse(sessionKeyBase64, token, rotationRequired);
    } finally {
      // The base64 String still has to reach the client, so this does not make the key
      // unrecoverable from the heap — it just stops the raw copy outliving the request.
      Arrays.fill(sessionKey, (byte) 0);
    }
  }
}
