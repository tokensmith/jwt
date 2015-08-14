package org.rootservices.jwt.marshaller;

import com.fasterxml.jackson.core.JsonProcessingException;
import org.rootservices.jwt.entity.RegisteredClaimNames;
import org.rootservices.jwt.entity.Token;

/**
 * Created by tommackenzie on 8/12/15.
 */
public interface TokenMarshaller {
    String tokenToString(Token token);
    Token stringToToken(String jwt, Class claimClass);
}
