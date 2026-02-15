package com.codeheadsystems.the.oprf;

import com.codeheadsystems.the.oprf.model.EliminationRequest;
import com.codeheadsystems.the.oprf.model.EliminationResponse;

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

}
