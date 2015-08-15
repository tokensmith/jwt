package helper.entity;

import com.fasterxml.jackson.annotation.JsonProperty;
import org.rootservices.jwt.entity.RegisteredClaimNames;

/**
 * Created by tommackenzie on 8/11/15.
 */
public class Claim extends RegisteredClaimNames {
    @JsonProperty(value="http://example.com/is_root")
    private Boolean uriIsRoot;

    public Boolean isUriIsRoot() {
        return uriIsRoot;
    }

    public void setUriIsRoot(Boolean uriIsRoot) {
        this.uriIsRoot = uriIsRoot;
    }
}
