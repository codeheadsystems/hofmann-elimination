package com.codeheadsystems.hofmann.server.manager;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.codeheadsystems.hofmann.model.opaque.AuthStartRequest;
import com.codeheadsystems.hofmann.server.ratelimit.RateLimitExceededException;
import com.codeheadsystems.hofmann.server.store.CredentialStore;
import com.codeheadsystems.hofmann.server.store.InMemoryCredentialStore;
import com.codeheadsystems.hofmann.server.store.InMemorySessionStore;
import com.codeheadsystems.hofmann.server.store.VersionedCredential;
import com.codeheadsystems.rfc.opaque.Client;
import com.codeheadsystems.rfc.opaque.Server;
import com.codeheadsystems.rfc.opaque.config.OpaqueConfig;
import com.codeheadsystems.rfc.opaque.model.ClientAuthState;
import com.codeheadsystems.rfc.opaque.model.ClientRegistrationState;
import com.codeheadsystems.rfc.opaque.model.RegistrationRecord;
import com.codeheadsystems.rfc.opaque.model.RegistrationResponse;
import com.codeheadsystems.rfc.opaque.testfixtures.OpaqueTestConfigs;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * {@code authStart} must not reveal whether a credential exists through how long it takes.
 *
 * <p>The protocol work was equalised first, and that measurement was taken against
 * {@link InMemoryCredentialStore}, where it reported AUC 0.5015 over 18,000 samples — no signal.
 * The store was the reason. A {@code ConcurrentHashMap} answers a hit and a miss in the same few
 * hundred nanoseconds, so the in-memory store <em>cannot</em> exhibit what leaks in production: the
 * documented store is JDBC- or Redis-backed, where an index probe that finds a row returns it and
 * one that does not returns early, a difference measured in milliseconds rather than nanoseconds.
 *
 * <p>So these tests use a store that behaves like a persistent one, and the store's own gap is
 * measured in the same run as the control — without a floor, that gap is exactly what an attacker
 * reads off the endpoint. A version of this test written against the plain in-memory store would
 * pass whether or not the fix existed, which is how the residual survived the first round of
 * measurement.
 *
 * <p>Rate limiters are wide open here on purpose. With the default auth limiter — burst 10, refill
 * 10/min — the concurrency test below would see {@code RateLimitExceededException} from the
 * limiter and pass without the concurrency ceiling existing at all.
 */
class AuthStartStoreTimingTest {

  private static final byte[] JWT_SECRET = "test-secret-must-be-at-least-32-bytes!".getBytes();
  private static final byte[] ALICE = "alice@example.com".getBytes(StandardCharsets.UTF_8);
  private static final byte[] UNKNOWN = "nobody@example.com".getBytes(StandardCharsets.UTF_8);
  private static final byte[] PASSWORD = "correct-horse-battery".getBytes(StandardCharsets.UTF_8);
  private static final OpaqueConfig CONFIG = OpaqueTestConfigs.forTesting();

  /** The floor in {@code HofmannOpaqueServerManager}, mirrored so the arithmetic below is legible. */
  private static final long FLOOR_MILLIS = 25L;

  /** A hit/miss gap comfortably inside the floor: the case the floor is meant to absorb. */
  private static final long INSIDE_FLOOR_MILLIS = 10L;

  /** A hit/miss gap larger than the floor: the documented case the floor does not absorb. */
  private static final long BEYOND_FLOOR_MILLIS = 45L;

  /** {@code MAX_CONCURRENT_AUTH_START}, mirrored. */
  private static final int CEILING = 128;

  private Client client;
  private Server server;
  private SlowOnHitCredentialStore credentialStore;
  private HofmannOpaqueServerManager manager;

  /**
   * A store that answers a hit slower than a miss, the way an indexed lookup does.
   *
   * <p>Delegates to the real in-memory store and adds latency only on the branch that finds
   * something — the shape of the leak, not a mock of it.
   */
  private static final class SlowOnHitCredentialStore implements CredentialStore {
    private final InMemoryCredentialStore delegate = new InMemoryCredentialStore();
    private final long hitDelayMillis;

    /**
     * When set, every lookup parks here instead of sleeping, and {@link #inside} counts how many
     * calls are currently held. That turns "are more than the ceiling admitted at once?" into a
     * question with a definite answer rather than one that depends on how the scheduler happened
     * to interleave 128 thread starts.
     */
    private volatile CountDownLatch gate;
    private final AtomicInteger inside = new AtomicInteger();

    SlowOnHitCredentialStore(long hitDelayMillis) {
      this.hitDelayMillis = hitDelayMillis;
    }

    @Override
    public void store(byte[] credentialIdentifier, RegistrationRecord record) {
      delegate.store(credentialIdentifier, record);
    }

    @Override
    public void store(byte[] credentialIdentifier, RegistrationRecord record, int keyVersion) {
      delegate.store(credentialIdentifier, record, keyVersion);
    }

    @Override
    public boolean storeIfAbsent(byte[] credentialIdentifier, RegistrationRecord record,
                                 int keyVersion) {
      return delegate.storeIfAbsent(credentialIdentifier, record, keyVersion);
    }

    @Override
    public Optional<RegistrationRecord> load(byte[] credentialIdentifier) {
      Optional<RegistrationRecord> found = delegate.load(credentialIdentifier);
      if (found.isPresent()) {
        sleep();
      }
      return found;
    }

    @Override
    public Optional<VersionedCredential> loadVersioned(byte[] credentialIdentifier) {
      Optional<VersionedCredential> found = delegate.loadVersioned(credentialIdentifier);
      CountDownLatch held = gate;
      if (held != null) {
        inside.incrementAndGet();
        try {
          held.await();
        } catch (InterruptedException e) {
          Thread.currentThread().interrupt();
        } finally {
          inside.decrementAndGet();
        }
        return found;
      }
      if (found.isPresent()) {
        sleep();
      }
      return found;
    }

    @Override
    public void delete(byte[] credentialIdentifier) {
      delegate.delete(credentialIdentifier);
    }

    private void sleep() {
      try {
        Thread.sleep(hitDelayMillis);
      } catch (InterruptedException e) {
        Thread.currentThread().interrupt();
      }
    }
  }

  @BeforeEach
  void setUp() {
    client = new Client(CONFIG);
    server = Server.generate(CONFIG);
    credentialStore = new SlowOnHitCredentialStore(INSIDE_FLOOR_MILLIS);
    manager = newManager(credentialStore);
    register(credentialStore, ALICE);
  }

  @AfterEach
  void tearDown() {
    manager.shutdown();
  }

  private HofmannOpaqueServerManager newManager(CredentialStore store) {
    return new HofmannOpaqueServerManager(
        () -> new OpaqueServerKeyDetail(server), store,
        new JwtManager(JWT_SECRET, "test-issuer", 3600, new InMemorySessionStore()),
        key -> true, key -> true);
  }

  private void register(CredentialStore store, byte[] credentialIdentifier) {
    ClientRegistrationState regState = client.createRegistrationRequest(PASSWORD);
    RegistrationResponse response =
        server.createRegistrationResponse(regState.request(), credentialIdentifier);
    RegistrationRecord record = client.finalizeRegistration(regState, response, null, null);
    store.store(credentialIdentifier, record, 0);
  }

  private long timeAuthStart(HofmannOpaqueServerManager target, byte[] credentialIdentifier) {
    ClientAuthState authState = client.generateKE1(PASSWORD);
    AuthStartRequest req = new AuthStartRequest(credentialIdentifier, authState.ke1());
    long start = System.nanoTime();
    target.authStart(req);
    return System.nanoTime() - start;
  }

  /**
   * Medians in <em>microseconds</em>, not milliseconds.
   *
   * <p>An earlier version truncated to whole milliseconds, which is 30–50x too coarse to see the
   * ~20&micro;s residual a reviewer measured coming out of {@code sleepUntil}'s overshoot — so the
   * test could not have supported the word "identical" whatever it asserted. Microseconds can.
   */
  private static long medianMicros(List<Long> nanos) {
    List<Long> sorted = new ArrayList<>(nanos);
    sorted.sort(Long::compare);
    return sorted.get(sorted.size() / 2) / 1_000L;
  }

  /**
   * Interleaved samples of both branches, plus the store's own gap as the control.
   *
   * <p>Interleaved rather than run in two blocks so that a machine which drifts — a CPU that ramps,
   * a GC that lands in one half — cannot masquerade as a signal in either direction.
   *
   * <p>Medians rather than means: one descheduled sample adds tens of milliseconds to a mean and
   * nothing to a median, and the property under test is what an attacker reads per probe.
   */
  private record Measurement(long observedGapMicros, long storeGapMicros,
                             long registeredMicros, long unregisteredMicros) {
  }

  private Measurement measure(HofmannOpaqueServerManager target, SlowOnHitCredentialStore store) {
    int samples = 31;
    List<Long> registered = new ArrayList<>();
    List<Long> unregistered = new ArrayList<>();
    List<Long> storeHit = new ArrayList<>();
    List<Long> storeMiss = new ArrayList<>();

    // The first calls through pay class loading and JIT on whichever branch happens to run first.
    timeAuthStart(target, ALICE);
    timeAuthStart(target, UNKNOWN);

    for (int i = 0; i < samples; i++) {
      registered.add(timeAuthStart(target, ALICE));
      unregistered.add(timeAuthStart(target, UNKNOWN));

      long t0 = System.nanoTime();
      store.loadVersioned(ALICE);
      storeHit.add(System.nanoTime() - t0);

      long t1 = System.nanoTime();
      store.loadVersioned(UNKNOWN);
      storeMiss.add(System.nanoTime() - t1);
    }

    return new Measurement(
        Math.abs(medianMicros(registered) - medianMicros(unregistered)),
        medianMicros(storeHit) - medianMicros(storeMiss),
        medianMicros(registered),
        medianMicros(unregistered));
  }

  /**
   * A store gap inside the floor is absorbed: what reaches the caller is microseconds, not
   * milliseconds.
   *
   * <p><strong>What this catches, and what it does not.</strong> It catches the gross failure —
   * the store's millisecond-scale gap arriving at the caller, which is what happens if the floor is
   * removed, mis-scoped, or started after the lookup. It does <em>not</em> catch the
   * tens-of-microseconds channels that came out of <em>how</em> {@code sleepUntil} waits: a
   * reviewer reverted that part of the fix and all five tests here still passed. Detecting those
   * needs hundreds of interleaved samples and a Mann-Whitney statistic — minutes of wall clock,
   * and not stable enough on a shared CI box to gate a build. Those numbers live on
   * {@code FLOOR_SETTLE_NANOS} and {@code AUTH_START_MIN_NANOS} with the harness that produced
   * them; this test does not pretend to stand in for them.
   *
   * <p>The 1 ms tolerance is set accordingly: an order of magnitude below the ~10 ms leak it does
   * guard against, and above what a loaded machine adds to a median of 31. It has been both
   * tighter and looser: at 250&micro;s a reviewer saw it fail 4 times out of 4 under a 16-thread
   * load (observed gaps 641–1188&micro;s) and once in 8 on an idle box, which is a test that
   * reports the machine rather than the code. At 1 ms it also stops half-detecting the reverted
   * wait strategy — that was catching it 4 times in 25, which is worse than not catching it,
   * because an intermittent red is read as flakiness and muted.
   */
  @Test
  void theStoresHitMissGapDoesNotReachTheCaller() {
    Measurement m = measure(manager, credentialStore);

    // The control. If the stand-in store does not leak, everything below is vacuous — which is
    // exactly the failure mode of the measurement that missed this residual.
    assertThat(m.storeGapMicros())
        .as("the stand-in store must actually leak, or this test proves nothing")
        .isGreaterThanOrEqualTo((INSIDE_FLOOR_MILLIS - 2) * 1_000L);

    assertThat(m.registeredMicros())
        .as("the floor must hold on the registered branch")
        .isGreaterThanOrEqualTo((FLOOR_MILLIS - 1) * 1_000L);
    assertThat(m.unregisteredMicros())
        .as("the floor must hold on the unregistered branch")
        .isGreaterThanOrEqualTo((FLOOR_MILLIS - 1) * 1_000L);

    assertThat(m.observedGapMicros())
        .as("store leaked %d us; %d us of it reached the caller",
            m.storeGapMicros(), m.observedGapMicros())
        .isLessThan(1_000L);
  }

  /**
   * A store slower than the floor leaks again — the documented limit, held as a measurement.
   *
   * <p><strong>This test does not guard the fix, and saying otherwise would be false.</strong> A
   * reviewer removed the floor entirely and this test still passed, because a 45 ms store gap
   * arrives at the caller either way. What it pins is the ceiling of the floor's reach: if someone
   * raised {@code AUTH_START_MIN_NANOS} past 45 ms, or made the floor do something other than what
   * it claims, this would fail. The test that fails when the fix is removed is
   * {@link #theStoresHitMissGapDoesNotReachTheCaller}.
   *
   * <p>Deliberately not probed at the boundary. The real edge is near 22 ms — {@code authStart}'s
   * own ~1.8 ms of work eats into the 25 ms — but that figure is a property of the machine, so a
   * test placed there would fail on a slower box for a reason that is not a defect. The boundary is
   * recorded on {@code AUTH_START_MIN_NANOS} with the numbers behind it instead.
   */
  @Test
  void aStoreSlowerThanTheFloorStillLeaks() {
    SlowOnHitCredentialStore slowStore = new SlowOnHitCredentialStore(BEYOND_FLOOR_MILLIS);
    HofmannOpaqueServerManager slow = newManager(slowStore);
    try {
      register(slowStore, ALICE);
      Measurement m = measure(slow, slowStore);

      assertThat(m.observedGapMicros())
          .as("a %d ms store gap exceeds the %d ms floor, so it must still be observable",
              BEYOND_FLOOR_MILLIS, FLOOR_MILLIS)
          .isGreaterThan((BEYOND_FLOOR_MILLIS - FLOOR_MILLIS - 5) * 1_000L);
    } finally {
      slow.shutdown();
    }
  }

  /**
   * A refusal at the ceiling must not spend the caller's rate-limit budget.
   *
   * <p>The limiter used to be consumed before the ceiling was checked, which read as prudent — do
   * not let a doomed request take a slot — and cost the wrong party. A reviewer held the ceiling
   * full and measured a legitimate user refused 10/10 during the flood and still refused 5/5 after
   * it drained: her whole burst spent on refusals the server chose to make. This asserts the
   * ordering that fixes it, with the real limiter rather than an open one.
   */
  @Test
  void aCeilingRefusalDoesNotBurnTheCallersRateLimit() throws Exception {
    HofmannOpaqueServerManager metered = new HofmannOpaqueServerManager(
        server, credentialStore,
        new JwtManager(JWT_SECRET, "test-issuer", 3600, new InMemorySessionStore()));
    try {
      CountDownLatch gate = new CountDownLatch(1);
      CountDownLatch parked = new CountDownLatch(CEILING);
      credentialStore.gate = gate;

      List<Thread> threads = new ArrayList<>();
      for (int i = 0; i < CEILING; i++) {
        // Distinct identifiers, so the flood never touches Alice's own limiter bucket.
        byte[] attacker = ("attacker-" + i + "@example.com").getBytes(StandardCharsets.UTF_8);
        AuthStartRequest req = new AuthStartRequest(attacker, client.generateKE1(PASSWORD).ke1());
        Thread t = new Thread(() -> {
          try {
            metered.authStart(req);
          } catch (RuntimeException ignored) {
            // Whatever happens to the flood is not what this test is about.
          } finally {
            parked.countDown();
          }
        });
        threads.add(t);
        t.start();
      }

      long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(30);
      while (credentialStore.inside.get() < CEILING && System.nanoTime() < deadline) {
        Thread.sleep(5);
      }
      assertThat(credentialStore.inside.get()).isEqualTo(CEILING);

      // Alice is refused while the ceiling is full. That much is the trade being made.
      for (int i = 0; i < 12; i++) {
        AuthStartRequest req = new AuthStartRequest(ALICE, client.generateKE1(PASSWORD).ke1());
        assertThatThrownBy(() -> metered.authStart(req))
            .isInstanceOf(RateLimitExceededException.class);
      }

      gate.countDown();
      credentialStore.gate = null;
      assertThat(parked.await(30, TimeUnit.SECONDS)).isTrue();
      for (Thread t : threads) {
        t.join(TimeUnit.SECONDS.toMillis(5));
      }

      // And once it drains she is served immediately — her burst of 10 was never spent. Refilling
      // it would take a minute, so if this passes the tokens were not consumed.
      assertThat(timeAuthStart(metered, ALICE))
          .as("12 ceiling refusals must not have drained a burst of 10")
          .isPositive();
    } finally {
      metered.shutdown();
    }
  }

  /**
   * The floor parks a request thread, so the number it can park must be bounded.
   *
   * <p>Exactly the finding raised against {@code recoveryVerify}'s floor and fixed with a semaphore
   * there. Adding a floor to the login path without the same cap would have reintroduced it on the
   * busier of the two endpoints, so it is asserted rather than assumed.
   *
   * <p><strong>Held open rather than raced.</strong> The obvious version of this test launches more
   * threads than the ceiling and asserts that some were refused; it passed in isolation and failed
   * under a loaded machine, because 128 thread starts can stagger past the 25 ms floor and then
   * nothing overlaps. Parking every admitted request in the store until this test releases it makes
   * the state definite: the ceiling is provably full when the assertion runs, so the result no
   * longer depends on the scheduler.
   */
  @Test
  void concurrencyInsideTheFloorIsCapped() throws Exception {
    int ceiling = CEILING;
    CountDownLatch gate = new CountDownLatch(1);
    CountDownLatch done = new CountDownLatch(ceiling);
    credentialStore.gate = gate;

    List<Thread> parked = new ArrayList<>();
    for (int i = 0; i < ceiling; i++) {
      AuthStartRequest req = new AuthStartRequest(UNKNOWN, client.generateKE1(PASSWORD).ke1());
      Thread t = new Thread(() -> {
        try {
          manager.authStart(req);
        } finally {
          done.countDown();
        }
      });
      parked.add(t);
      t.start();
    }

    try {
      // Every one of these must be admitted — there are exactly as many as there are slots — so
      // waiting for all of them to reach the store is not a race, it is the precondition.
      long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(30);
      while (credentialStore.inside.get() < ceiling && System.nanoTime() < deadline) {
        Thread.sleep(5);
      }
      assertThat(credentialStore.inside.get())
          .as("all %d slots should be occupied before the ceiling is probed", ceiling)
          .isEqualTo(ceiling);

      AuthStartRequest overflow =
          new AuthStartRequest(UNKNOWN, client.generateKE1(PASSWORD).ke1());
      assertThatThrownBy(() -> manager.authStart(overflow))
          .as("with every slot held, the next call must be refused rather than queued — queueing "
              + "consumes the request threads the ceiling exists to protect")
          .isInstanceOf(RateLimitExceededException.class);
    } finally {
      gate.countDown();
      credentialStore.gate = null;
    }

    assertThat(done.await(30, TimeUnit.SECONDS))
        .as("the parked calls must all complete once released")
        .isTrue();
    for (Thread t : parked) {
      t.join(TimeUnit.SECONDS.toMillis(5));
    }

    // And the permits come back, so a full ceiling is a transient condition rather than a wedge.
    assertThat(timeAuthStart(manager, UNKNOWN))
        .as("after the parked calls drain, a fresh call must be admitted again")
        .isPositive();
  }

  /** A permit leaked on any exit path would wedge authentication permanently after enough calls. */
  @Test
  void permitsAreReleasedAcrossManyCalls() {
    for (int i = 0; i < 80; i++) {
      timeAuthStart(manager, i % 2 == 0 ? ALICE : UNKNOWN);
    }
    assertThat(timeAuthStart(manager, ALICE))
        .as("after many calls a fresh one must still be admitted")
        .isPositive();
  }
}
