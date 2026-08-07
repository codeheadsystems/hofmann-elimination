package com.codeheadsystems.hofmann.dropwizard;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

/**
 * The per-path body-size limit looks up a normalised path, so it cannot silently stop applying
 * because a container reports the path with or without a leading slash.
 *
 * <p>That failure mode is the reason this is normalised rather than asserted: a mismatch would not
 * throw or fail a request, the tighter bound would just quietly fall back to the generic one and
 * the batch endpoints would lose their protection.
 */
class HofmannBundlePathNormalizationTest {

  @Test
  void stripsALeadingSlashWhenPresent() {
    assertThat(HofmannBundle.normalizePath("/oprf/verifiable")).isEqualTo("oprf/verifiable");
  }

  @Test
  void leavesAPathWithoutALeadingSlashAlone() {
    assertThat(HofmannBundle.normalizePath("oprf/verifiable")).isEqualTo("oprf/verifiable");
  }

  /**
   * Jersey's path pattern for a resource method is {@code /verifiable(/)?}, so
   * {@code POST /oprf/verifiable/} routes to the same method while {@code getPath()} reports the
   * trailing slash. Matching the raw string missed, dropping the request back to the generic
   * 64 KiB limit and restoring the amplification the cap-derived bound exists to close — for one
   * extra character, unauthenticated.
   */
  @Test
  void stripsATrailingSlash() {
    assertThat(HofmannBundle.normalizePath("oprf/verifiable/")).isEqualTo("oprf/verifiable");
    assertThat(HofmannBundle.normalizePath("/oprf/verifiable/")).isEqualTo("oprf/verifiable");
  }

  @Test
  void stripsRepeatedTrailingSlashes() {
    // `//` routes as well, so one strip is not enough.
    assertThat(HofmannBundle.normalizePath("/oprf/verifiable//")).isEqualTo("oprf/verifiable");
  }

  @Test
  void aPathOfOnlySlashesDoesNotUnderflow() {
    assertThat(HofmannBundle.normalizePath("/")).isEmpty();
    assertThat(HofmannBundle.normalizePath("///")).isEmpty();
  }

  @Test
  void nullBecomesEmptyRatherThanThrowing() {
    // Map.of is null-hostile, so a null path reaching getOrDefault would throw out of a filter
    // that runs in front of every request.
    assertThat(HofmannBundle.normalizePath(null)).isEmpty();
  }
}
