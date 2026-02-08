package com.codeheadsystems.hofman;

public interface Server {

  /**
   * Essentially, the server takes the blinded point from the client and multiplies it by a secret scalar value that is
   * unique to the server. This process transforms the blinded point into a new point on the elliptic curve, which is
   * then returned to the client in a hex-encoded format. That process is difficult to reverse due to computational
   * complexity. However, to reverse it is subject to attack from quantum computers by the first party.
   *
   * @param eliminationRequest
   * @return
   */
  EliminationResponse process(EliminationRequest eliminationRequest);

  /**
   * Generates a client key that contains the client's unique identifier and the scalar value used in the blinding process.
   * The server will store this later for the elimination process.
   * @param clientIdentifier A unique identifier for the client, which can be used to track and manage client keys.
   * @return A reusable ClientKey record that contains the client's unique identifier and the scalar value used in the blinding process.
   */
  ClientKey generateClientKey(String clientIdentifier);

}
