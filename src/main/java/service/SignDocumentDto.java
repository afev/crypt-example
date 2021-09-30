package service;

import lombok.Getter;
import lombok.Setter;

import java.io.Serializable;
import java.util.UUID;

@Getter
@Setter
public class SignDocumentDto implements Serializable {
    private static final long serialVersionUID = -500994703310549891L;
    private UUID id;
    private String name;
    private String signedBy;
    private byte[] signature;
    private String fileName;
    private String fileId;
    private String error;

    public byte[] getSignature() {
        return signature.clone();
    }

    public void setSignature(byte[] signature) {
        this.signature = signature != null ? signature.clone() : null;
    }

    @Override
    public String toString() {
        return "SignDocumentDto{" +
                "id=" + id +
                ", name='" + name + '\'' +
                ", signedBy='" + signedBy + '\'' +
                '}';
    }

}
