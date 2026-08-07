package com.codeheadsystems.hofmann.springboot.config;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * Unit tests for {@link BodySizeLimitFilter}, including the {@code getReader()} path which would
 * otherwise bypass the bound by delegating to the unwrapped request.
 */
class BodySizeLimitFilterTest {

  private static final byte[] OVERSIZED = "0123456789ABCDEFGHIJ".getBytes(StandardCharsets.UTF_8); // 20 bytes

  private HttpServletRequest chunkedRequest(byte[] body) throws IOException {
    HttpServletRequest request = mock(HttpServletRequest.class);
    when(request.getContentLengthLong()).thenReturn(-1L); // chunked: no declared length
    when(request.getCharacterEncoding()).thenReturn("UTF-8");
    when(request.getInputStream()).thenReturn(new FakeServletInputStream(body));
    return request;
  }

  @Test
  void getReader_boundsOversizedChunkedBody() throws Exception {
    BodySizeLimitFilter filter = new BodySizeLimitFilter(10);
    HttpServletRequest request = chunkedRequest(OVERSIZED);
    HttpServletResponse response = mock(HttpServletResponse.class);

    FilterChain chain = (req, res) -> {
      // Read the body via getReader() — the path that previously escaped the bound.
      BufferedReader reader = ((HttpServletRequest) req).getReader();
      char[] buf = new char[64];
      while (reader.read(buf) != -1) {
        // drain
      }
    };

    assertThatThrownBy(() -> filter.doFilterInternal(request, response, chain))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("exceeds maximum");
  }

  @Test
  void getInputStream_boundsOversizedChunkedBody() throws Exception {
    BodySizeLimitFilter filter = new BodySizeLimitFilter(10);
    HttpServletRequest request = chunkedRequest(OVERSIZED);
    HttpServletResponse response = mock(HttpServletResponse.class);

    FilterChain chain = (req, res) -> {
      ServletInputStream in = ((HttpServletRequest) req).getInputStream();
      byte[] buf = new byte[64];
      while (in.read(buf) != -1) {
        // drain
      }
    };

    assertThatThrownBy(() -> filter.doFilterInternal(request, response, chain))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("exceeds maximum");
  }

  @Test
  void declaredLengthOverLimit_rejectedWith413() throws Exception {
    BodySizeLimitFilter filter = new BodySizeLimitFilter(10);
    HttpServletRequest request = mock(HttpServletRequest.class);
    when(request.getContentLengthLong()).thenReturn(100L);
    HttpServletResponse response = mock(HttpServletResponse.class);
    FilterChain chain = mock(FilterChain.class);

    filter.doFilterInternal(request, response, chain);

    verify(response).sendError(HttpServletResponse.SC_REQUEST_ENTITY_TOO_LARGE,
        "Request body exceeds maximum allowed size");
    verify(chain, never()).doFilter(org.mockito.ArgumentMatchers.any(), org.mockito.ArgumentMatchers.any());
  }

  @Test
  void bodyWithinLimit_passesThrough() throws Exception {
    BodySizeLimitFilter filter = new BodySizeLimitFilter(64);
    byte[] small = "small body".getBytes(StandardCharsets.UTF_8);
    HttpServletRequest request = chunkedRequest(small);
    HttpServletResponse response = mock(HttpServletResponse.class);

    StringBuilder read = new StringBuilder();
    FilterChain chain = (req, res) -> {
      BufferedReader reader = ((HttpServletRequest) req).getReader();
      int c;
      while ((c = reader.read()) != -1) {
        read.append((char) c);
      }
    };

    filter.doFilterInternal(request, response, chain);

    assertThat(read.toString()).isEqualTo("small body");
  }

  /** Minimal ServletInputStream over a byte array for filter tests. */
  private static final class FakeServletInputStream extends ServletInputStream {
    private final ByteArrayInputStream delegate;

    FakeServletInputStream(byte[] data) {
      this.delegate = new ByteArrayInputStream(data);
    }

    @Override
    public int read() {
      return delegate.read();
    }

    @Override
    public int read(byte[] b, int off, int len) {
      return delegate.read(b, off, len);
    }

    @Override
    public boolean isFinished() {
      return delegate.available() == 0;
    }

    @Override
    public boolean isReady() {
      return true;
    }

    @Override
    public void setReadListener(ReadListener readListener) {
      throw new UnsupportedOperationException();
    }
  }

  // ─── per-path limits ────────────────────────────────────────────────────────

  private HttpServletRequest requestAt(String uri, String contextPath, long declaredLength) {
    HttpServletRequest request = mock(HttpServletRequest.class);
    when(request.getContentLengthLong()).thenReturn(declaredLength);
    when(request.getRequestURI()).thenReturn(uri);
    when(request.getContextPath()).thenReturn(contextPath);
    return request;
  }

  @Test
  void perPathLimit_appliesToTheMatchingPath() throws Exception {
    BodySizeLimitFilter filter = new BodySizeLimitFilter(1000, Map.of("/oprf/verifiable", 100L));
    HttpServletResponse response = mock(HttpServletResponse.class);
    FilterChain chain = mock(FilterChain.class);

    // Within the generic limit but over the per-path one.
    filter.doFilter(requestAt("/oprf/verifiable", "", 500), response, chain);

    verify(response).sendError(eq(HttpServletResponse.SC_REQUEST_ENTITY_TOO_LARGE), any());
    verify(chain, never()).doFilter(any(), any());
  }

  @Test
  void perPathLimit_leavesOtherPathsOnTheGenericLimit() throws Exception {
    BodySizeLimitFilter filter = new BodySizeLimitFilter(1000, Map.of("/oprf/verifiable", 100L));
    HttpServletResponse response = mock(HttpServletResponse.class);
    FilterChain chain = mock(FilterChain.class);

    filter.doFilter(requestAt("/opaque/auth/start", "", 500), response, chain);

    verify(response, never()).sendError(anyInt(), any());
    verify(chain).doFilter(any(), any());
  }

  /**
   * A size bound that stops applying because someone set an unrelated config property is the
   * worst kind: nothing fails, the protection is simply gone. {@code getRequestURI()} is
   * contextPath + servletPath + pathInfo, so an app under {@code server.servlet.context-path}
   * presents "/api/oprf/verifiable" against a key of "/oprf/verifiable".
   */
  @Test
  void perPathLimit_stillAppliesUnderAServletContextPath() throws Exception {
    BodySizeLimitFilter filter = new BodySizeLimitFilter(1000, Map.of("/oprf/verifiable", 100L));
    HttpServletResponse response = mock(HttpServletResponse.class);
    FilterChain chain = mock(FilterChain.class);

    filter.doFilter(requestAt("/api/oprf/verifiable", "/api", 500), response, chain);

    verify(response).sendError(eq(HttpServletResponse.SC_REQUEST_ENTITY_TOO_LARGE), any());
    verify(chain, never()).doFilter(any(), any());
  }

  @Test
  void perPathLimit_neverLoosensTheGenericLimit() throws Exception {
    // min(), not the override outright: a deployment that lowers the generic limit means it.
    BodySizeLimitFilter filter = new BodySizeLimitFilter(50, Map.of("/oprf/verifiable", 100L));
    HttpServletResponse response = mock(HttpServletResponse.class);
    FilterChain chain = mock(FilterChain.class);

    filter.doFilter(requestAt("/oprf/verifiable", "", 80), response, chain);

    verify(response).sendError(eq(HttpServletResponse.SC_REQUEST_ENTITY_TOO_LARGE), any());
  }

  @Test
  void nullRequestUri_fallsBackRatherThanThrowing() throws Exception {
    // Map.copyOf is null-hostile, so get(null) would throw out of a filter in front of every
    // request. The generic limit is the safe answer when the path is unknown.
    BodySizeLimitFilter filter = new BodySizeLimitFilter(1000, Map.of("/oprf/verifiable", 100L));
    HttpServletResponse response = mock(HttpServletResponse.class);
    FilterChain chain = mock(FilterChain.class);

    filter.doFilter(requestAt(null, null, 500), response, chain);

    verify(chain).doFilter(any(), any());
  }
}
