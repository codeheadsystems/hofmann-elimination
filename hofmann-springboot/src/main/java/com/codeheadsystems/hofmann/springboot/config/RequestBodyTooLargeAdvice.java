package com.codeheadsystems.hofmann.springboot.config;

import com.codeheadsystems.hofmann.springboot.controller.OpaqueController;
import com.codeheadsystems.hofmann.springboot.controller.OprfController;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/**
 * Maps an over-limit request body to HTTP 413 on the Hofmann endpoints.
 *
 * <p>Scoped to this library's two controllers with {@code assignableTypes} rather than declared
 * globally. A library that installs an application-wide {@code @RestControllerAdvice} silently
 * changes how a consumer's own endpoints report errors, which is not a decision it gets to make.
 *
 * <p>The body limit is enforced twice — an up-front {@code Content-Length} check, and a bound on
 * the stream for chunked bodies that declare no length. Only the first produced a 413. The second
 * threw from inside {@code ServletInputStream.read}, where Jackson wraps it in
 * {@link HttpMessageNotReadableException}, and with no handler that became a 500: the server
 * blaming itself for a request the client made too large. Dropwizard already answered 413 for the
 * identical request, so this also stops the two integrations disagreeing.
 */
@RestControllerAdvice(assignableTypes = {OpaqueController.class, OprfController.class})
public class RequestBodyTooLargeAdvice {

  /**
   * Handles the exception thrown directly by the bounded stream.
   *
   * @param e the exception
   * @return a 413 response
   */
  @ExceptionHandler(RequestBodyTooLargeException.class)
  public ResponseEntity<String> handle(final RequestBodyTooLargeException e) {
    return ResponseEntity.status(HttpStatus.PAYLOAD_TOO_LARGE)
        .body("Request body exceeds maximum allowed size");
  }

  /**
   * Handles the same exception after Jackson has wrapped it.
   *
   * <p>Body reading happens during argument resolution, so the bound fires inside the message
   * converter and arrives here wrapped. Anything else that fails to parse is a genuine 400 and is
   * rethrown so the existing behaviour is untouched.
   *
   * @param e the wrapping exception
   * @return a 413 response
   * @throws HttpMessageNotReadableException if the cause is not an over-limit body
   */
  @ExceptionHandler(HttpMessageNotReadableException.class)
  public ResponseEntity<String> handleWrapped(final HttpMessageNotReadableException e) {
    for (Throwable cause = e.getCause(); cause != null; cause = cause.getCause()) {
      if (cause instanceof RequestBodyTooLargeException) {
        return ResponseEntity.status(HttpStatus.PAYLOAD_TOO_LARGE)
            .body("Request body exceeds maximum allowed size");
      }
    }
    throw e;
  }
}
