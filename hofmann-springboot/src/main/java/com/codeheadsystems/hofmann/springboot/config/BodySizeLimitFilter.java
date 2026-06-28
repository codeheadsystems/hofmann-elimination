package com.codeheadsystems.hofmann.springboot.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
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

  /**
   * Instantiates a new Body size limit filter.
   *
   * @param maxBytes the maximum allowed request body size in bytes
   */
  public BodySizeLimitFilter(long maxBytes) {
    this.maxBytes = maxBytes;
  }

  @Override
  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                  FilterChain filterChain) throws ServletException, IOException {
    long declaredLength = request.getContentLengthLong();
    if (declaredLength > maxBytes) {
      response.sendError(HttpServletResponse.SC_REQUEST_ENTITY_TOO_LARGE,
          "Request body exceeds maximum allowed size");
      return;
    }
    filterChain.doFilter(new BoundedRequest(request, maxBytes), response);
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
