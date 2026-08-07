package com.codeheadsystems.hofmann.springboot.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import jakarta.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Rejects request bodies larger than a configured maximum, mirroring the Dropwizard adapter's
 * 64 KiB default. Guards the OPAQUE and OPRF endpoints against large-payload / base64-hex-decode
 * memory-amplification DoS. Handles both {@code Content-Length} and chunked transfer encoding:
 * a declared length over the limit is rejected up front with HTTP 413, and the request stream is
 * additionally bounded so a streamed (chunked) body is stopped while it is being read.
 */
public class BodySizeLimitFilter extends OncePerRequestFilter {

  private final long maxBytes;
  private final Map<String, Long> perPathMaxBytes;

  /**
   * Instantiates a new Body size limit filter.
   *
   * @param maxBytes the maximum allowed request body size in bytes
   */
  public BodySizeLimitFilter(long maxBytes) {
    this(maxBytes, Map.of());
  }

  /**
   * Instantiates a new Body size limit filter with tighter limits on specific paths.
   *
   * <p>The generic limit is one size for every endpoint, which is right for the OPAQUE messages —
   * they are fixed-width. It is loose for the batched verifiable OPRF endpoints, where the
   * meaningful bound is the batch cap: at 64 KiB and ~138 bytes per hex-encoded P-521 element,
   * the generic limit admits roughly 470 elements against a configured cap of 64. Every one of
   * those is read and materialised into a {@code List<String>} before the manager rejects the
   * batch, so the cap bounds the curve work but not the work before it.
   *
   * <p>A per-path limit derived from the cap closes that, and keeps the two in step if either is
   * retuned. It is applied here rather than in the resource because it has to act before the body
   * is parsed, which is the whole point.
   *
   * @param maxBytes        the default maximum request body size in bytes
   * @param perPathMaxBytes exact request paths mapped to their own, usually smaller, maximum
   */
  public BodySizeLimitFilter(long maxBytes, Map<String, Long> perPathMaxBytes) {
    this.maxBytes = maxBytes;
    this.perPathMaxBytes = Map.copyOf(perPathMaxBytes);
  }

  @Override
  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                  FilterChain filterChain) throws ServletException, IOException {
    long limit = limitFor(request);
    long declaredLength = request.getContentLengthLong();
    if (declaredLength > limit) {
      response.sendError(HttpServletResponse.SC_REQUEST_ENTITY_TOO_LARGE,
          "Request body exceeds maximum allowed size");
      return;
    }
    filterChain.doFilter(new BoundedRequest(request, limit), response);
  }

  /**
   * Resolves the limit for a request, taking the smaller of the generic limit and any per-path
   * override.
   *
   * <p>{@code min} rather than the override outright: a deployment that lowers the generic limit
   * below a per-path value means it, and a per-path entry should only ever tighten.
   */
  private long limitFor(HttpServletRequest request) {
    // Guard the null URI rather than assuming a container always supplies one. Map.copyOf is
    // null-hostile, so an absent URI would make get(null) throw straight out of a filter that sits
    // in front of every request — turning an odd request into a 500 for the whole endpoint. The
    // generic limit is the safe answer when the path is unknown.
    String path = request.getRequestURI();
    if (path == null) {
      return maxBytes;
    }
    Long override = perPathMaxBytes.get(path);
    return override == null ? maxBytes : Math.min(maxBytes, override);
  }

  /**
   * Request wrapper whose input stream is bounded to {@code maxBytes}.
   */
  private static final class BoundedRequest extends HttpServletRequestWrapper {
    private final long maxBytes;

    BoundedRequest(HttpServletRequest request, long maxBytes) {
      super(request);
      this.maxBytes = maxBytes;
    }

    @Override
    public ServletInputStream getInputStream() throws IOException {
      return new BoundedServletInputStream(super.getInputStream(), maxBytes);
    }

    @Override
    public BufferedReader getReader() throws IOException {
      // Route reader-based body access through the bounded input stream too; otherwise
      // HttpServletRequestWrapper.getReader() would delegate to the original (unbounded) request.
      String encoding = getCharacterEncoding();
      Charset charset = encoding != null ? Charset.forName(encoding) : StandardCharsets.UTF_8;
      return new BufferedReader(new InputStreamReader(getInputStream(), charset));
    }
  }

  /**
   * Servlet input stream that throws once more than {@code maxBytes} have been read, stopping an
   * oversized chunked body that declares no Content-Length.
   */
  private static final class BoundedServletInputStream extends ServletInputStream {
    private final ServletInputStream delegate;
    private final long maxBytes;
    private long count;

    BoundedServletInputStream(ServletInputStream delegate, long maxBytes) {
      this.delegate = delegate;
      this.maxBytes = maxBytes;
    }

    @Override
    public int read() throws IOException {
      int b = delegate.read();
      if (b != -1) {
        increment(1);
      }
      return b;
    }

    @Override
    public int read(byte[] b, int off, int len) throws IOException {
      int n = delegate.read(b, off, len);
      if (n > 0) {
        increment(n);
      }
      return n;
    }

    private void increment(int read) throws IOException {
      count += read;
      if (count > maxBytes) {
        throw new IOException("Request body exceeds maximum allowed size");
      }
    }

    @Override
    public boolean isFinished() {
      return delegate.isFinished();
    }

    @Override
    public boolean isReady() {
      return delegate.isReady();
    }

    @Override
    public void setReadListener(ReadListener readListener) {
      delegate.setReadListener(readListener);
    }
  }
}
