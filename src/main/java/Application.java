import service.PrivateKeyContext;
import service.Signer;

public class Application {

    public static void main(String[] args) throws Exception {
        for(int i = 0; i < 100; i++) {
            Signer signer = new Signer();
            PrivateKeyContext privateKey = signer.getPrivateKey();
            byte[] bytes = signer.signPkcs7(privateKey);
            System.out.println("Signature created successfully, length = " + bytes.length);
        }
        System.out.println("completed");
    }
}