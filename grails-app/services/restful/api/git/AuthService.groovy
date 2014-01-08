package restful.api.git

import org.springframework.beans.factory.InitializingBean

import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import javax.servlet.http.HttpServletRequest
import java.security.SignatureException

class AuthService implements InitializingBean {
    static scope = "singleton"

    def grailsApplication

    // this default key may be changed by the key entry defined in Config.groovy
    def key = "WakeServ"

    def final HMAC_SHA1_ALGORITHM = "HmacSHA1"

    @Override
    void afterPropertiesSet() throws Exception {
        this.key = grailsApplication.config.key
    }

    def String calculateHMAC(String data, String key) throws java.security.SignatureException {
        String result = "";
        try {

            if (!data.isEmpty() && !key.isEmpty()) {
                // get an hmac_sha1 key from the raw key bytes
                SecretKeySpec signingKey = new SecretKeySpec(key.getBytes(), HMAC_SHA1_ALGORITHM);

                // get an hmac_sha1 Mac instance and initialize with the signing key
                Mac mac = Mac.getInstance(HMAC_SHA1_ALGORITHM);
                mac.init(signingKey);

                // compute the hmac on input data bytes
                byte[] rawHmac = mac.doFinal(data.getBytes());

                // base64-encode the hmac
                result = rawHmac.encodeBase64().toString()
            } else {
                log.warn("data or key appears to be empty!");
            }
        } catch (Exception e) {
            throw new SignatureException("Failed to generate HMAC : " + e.getMessage());
        }
        return result;
    }

    public boolean isDataAuthenticated(String data, String signature) {
        def String newSignature = calculateHMAC(data, this.key)
        log.debug("re-calculated signature: " + newSignature)
        return newSignature.equals(signature)
    }

    private String getRequesterIp(HttpServletRequest req) {
        def ipAdd
        ipAdd = req.getHeader("Remote_Addr")
        if (ipAdd == null) {
            ipAdd = req.getHeader("HTTP_X_FORWARDED_FOR") ?: req.getRemoteAddr()
        }
        return ipAdd
    }

    private String getParamString(HttpServletRequest req) {

    }

    private boolean isExpired(HttpServletRequest req){

    }


}