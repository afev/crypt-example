package service;

import lombok.NoArgsConstructor;

import java.security.PrivateKey;
import java.security.cert.Certificate;

@NoArgsConstructor
public class PrivateKeyContext {
    private String error;
    private PrivateKey key;

    public String getError() {
        return error;
    }

    public void setError(String error) {
        this.error = error;
    }

    public PrivateKey getKey() {
        return key;
    }

    public void setKey(PrivateKey key) {
        this.key = key;
    }

    public Certificate getCertificate() {
        return certificate;
    }

    public void setCertificate(Certificate certificate) {
        this.certificate = certificate;
    }

    private Certificate certificate;

    public PrivateKeyContext(String error) {
        this.error = error;
    }

    public PrivateKeyContext(PrivateKey key, Certificate certificate) {
        this.key = key;
        this.certificate = certificate;
    }
}
