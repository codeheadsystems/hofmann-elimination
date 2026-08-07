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

  @Test
  void nullBecomesEmptyRatherThanThrowing() {
    // Map.of is null-hostile, so a null path reaching getOrDefault would throw out of a filter
    // that runs in front of every request.
    assertThat(HofmannBundle.normalizePath(null)).isEmpty();
  }
}
