package com.codeheadsystems.hofmann.server.store;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class InMemoryRecoveryTokenStoreTest {

  private InMemoryRecoveryTokenStore store;

  @BeforeEach
  void setUp() {
    store = new InMemoryRecoveryTokenStore();
  }

  @AfterEach
  void tearDown() {
    store.shutdown();
  }

  @Test
  void storeAndRemove() {
    store.store("token-1", "Y3JlZDE=");
    assertThat(store.remove("token-1")).contains("Y3JlZDE=");
  }

  @Test
  void removeIsConsumeOnce() {
    store.store("token-1", "Y3JlZDE=");
    assertThat(store.remove("token-1")).isPresent();
    assertThat(store.remove("token-1")).isEmpty();
  }

  @Test
  void removeUnknownTokenReturnsEmpty() {
    assertThat(store.remove("nonexistent")).isEmpty();
  }

  @Test
  void storeAndPeek() {
    store.store("token-1", "Y3JlZDE=");
    assertThat(store.peek("token-1")).contains("Y3JlZDE=");
    // peek does not consume
    assertThat(store.peek("token-1")).contains("Y3JlZDE=");
  }

  @Test
  void peekUnknownTokenReturnsEmpty() {
    assertThat(store.peek("nonexistent")).isEmpty();
  }

  @Test
  void expiredTokenReturnsEmpty() throws InterruptedException {
    InMemoryRecoveryTokenStore shortLived = new InMemoryRecoveryTokenStore(1, 100);
    try {
      shortLived.store("token-1", "Y3JlZDE=");
      Thread.sleep(1100);
      assertThat(shortLived.remove("token-1")).isEmpty();
    } finally {
      shortLived.shutdown();
    }
  }

  @Test
  void expiredTokenPeekReturnsEmpty() throws InterruptedException {
    InMemoryRecoveryTokenStore shortLived = new InMemoryRecoveryTokenStore(1, 100);
    try {
      shortLived.store("token-1", "Y3JlZDE=");
      Thread.sleep(1100);
      assertThat(shortLived.peek("token-1")).isEmpty();
    } finally {
      shortLived.shutdown();
    }
  }

  @Test
  void capacityLimitThrowsIllegalStateException() {
    InMemoryRecoveryTokenStore small = new InMemoryRecoveryTokenStore(600, 2);
    try {
      small.store("t1", "a");
      small.store("t2", "b");
      assertThatThrownBy(() -> small.store("t3", "c"))
          .isInstanceOf(IllegalStateException.class);
    } finally {
      small.shutdown();
    }
  }
}
