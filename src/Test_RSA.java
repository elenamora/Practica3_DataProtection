import javax.xml.crypto.dsig.SignedInfo;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.nio.charset.StandardCharsets;

public class Test_RSA {

	final static byte[] plaintext = "Fírmame esta".getBytes();

	public static void main(String[] args) throws Exception {
		RSALibrary r = new RSALibrary();
		r.generateKeys();

		/* Read  public key*/
		Path path = Paths.get("./public.key");
		byte[] bytes = Files.readAllBytes(path);
		//Public key is stored in x509 format
		X509EncodedKeySpec keyspec = new X509EncodedKeySpec(bytes);
		KeyFactory keyfactory = KeyFactory.getInstance("RSA");
		PublicKey publicKey = keyfactory.generatePublic(keyspec);

		/* Read private key */
		path = Paths.get("./private.key");
		byte[] bytes2 = Files.readAllBytes(path);
		//Private key is stored in PKCS8 format
		PKCS8EncodedKeySpec keyspec2 = new PKCS8EncodedKeySpec(bytes2);
		KeyFactory keyfactory2 = KeyFactory.getInstance("RSA");
		PrivateKey privateKey = keyfactory2.generatePrivate(keyspec2);

		byte[] ciphertext = r.encrypt(plaintext, publicKey);
		System.out.println(new String(r.decrypt(ciphertext, privateKey)));

		byte[] signedInfo = r.sign(plaintext, privateKey);
		System.out.println(r.verify(plaintext, signedInfo, publicKey));



	}

}
