package org.rootservices.jwt.entity.header;

/**
 * Created by tommackenzie on 8/9/15.
 *
 * JSON Object Signing and Encryption
 */
public class Header {
    Type type;

    public Type getType() {
        return type;
    }

    public void setType(Type type) {
        this.type = type;
    }
}
