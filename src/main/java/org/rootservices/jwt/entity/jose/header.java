package main.java.org.rootservices.jwt.entity.jose;

/**
 * Created by tommackenzie on 8/9/15.
 *
 * JSON Object Signing and Encryption
 */
public class header {
    Type type;

    public Type getType() {
        return type;
    }

    public void setType(Type type) {
        this.type = type;
    }
}
