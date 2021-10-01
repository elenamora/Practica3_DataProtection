import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;


public class EncryptionProcess {

    byte[] ciphertext;
    byte[] signedInfo;
    PublicKey publicKey;

    public PrivateKey decryptKey() throws Exception{
        System.out.println("Introduce tu clave para encriptar el texto");
        byte[] bytephrase;
        try {
            bytephrase = RSALibrary.generateByteSeq();
        }catch (IllegalArgumentException e){
            System.out.println(e.getMessage());
            bytephrase = RSALibrary.generateByteSeq();
        }
        Path path = Paths.get("./public.key");
        path = Paths.get("./private.key");
        byte[] pkencoded = Files.readAllBytes(path);

        SymmetricCipher symCip = new SymmetricCipher();
        byte[] pKbyte = symCip.decryptCBC(pkencoded, bytephrase);
        PKCS8EncodedKeySpec keyspec2 = new PKCS8EncodedKeySpec(pKbyte);
        KeyFactory keyfactory2 = KeyFactory.getInstance("RSA");

        return keyfactory2.generatePrivate(keyspec2);

    }

    public void encryptPlainText(byte[] plaintext, RSALibrary r, PrivateKey pk) throws Exception{
        /* Read  public key*/
        Path path = Paths.get("./public.key");
        byte[] bytes = Files.readAllBytes(path);
        //Public key is stored in x509 format
        X509EncodedKeySpec keyspec = new X509EncodedKeySpec(bytes);
        KeyFactory keyfactory = KeyFactory.getInstance("RSA");
        publicKey = keyfactory.generatePublic(keyspec);

        ciphertext = r.encrypt(plaintext, publicKey);
        signedInfo = r.sign(plaintext, pk);
    }

    public void decryptPlainText(RSALibrary r, PrivateKey pk) throws Exception{

        byte[] plaintext = r.decrypt(ciphertext, pk);

        if (r.verify(plaintext, signedInfo, publicKey)){
            System.out.println(new String(plaintext));
        }else {
            System.out.println("Not verified");
        }

    }

    public static void main(String[] args) throws Exception {
        final byte[] plaintext = "Encripta esta frase".getBytes();
        RSALibrary r = new RSALibrary();
        r.generateKeys();
        EncryptionProcess ep = new EncryptionProcess();

        PrivateKey pk = ep.decryptKey();
        ep.encryptPlainText(plaintext, r, pk);
        ep.decryptPlainText(r, pk);
    }
}

