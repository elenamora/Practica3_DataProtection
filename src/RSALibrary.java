import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Scanner;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;


public class RSALibrary {

    // String to hold name of the encryption algorithm.
    public final String ALGORITHM = "RSA";

    //String to hold the name of the private key file.
    public final String PRIVATE_KEY_FILE = "./private.key";

    // String to hold name of the public key file.
    public final String PUBLIC_KEY_FILE = "./public.key";

    /***********************************************************************************/
    /* Generates an RSA key pair (a public and a private key) of 1024 bits length */
    /* Stores the keys in the files defined by PUBLIC_KEY_FILE and PRIVATE_KEY_FILE */
    /* Throws IOException */
    /***********************************************************************************/
    public void generateKeys() throws IOException {

        try {

            final KeyPairGenerator keyGen = KeyPairGenerator.getInstance(ALGORITHM);
            keyGen.initialize(1024);

            // TO-DO: Use KeyGen to generate a public and a private key
            // ...
            KeyPair kp = keyGen.generateKeyPair();
            PublicKey publicKey = kp.getPublic();
            PrivateKey privateKey = kp.getPrivate();

            byte[] bytephrase = new byte[16];

            try {
                bytephrase = generateByteSeq();
            }catch (IllegalArgumentException e){
                System.out.println(e.getMessage());
                bytephrase = generateByteSeq();
            }

            // TO-DO: store the public key in the file PUBLIC_KEY_FILE
            // ...
            File publicFile = new File(PUBLIC_KEY_FILE);
            FileOutputStream outPublic = new FileOutputStream(publicFile);
            outPublic.write(publicKey.getEncoded());
            outPublic.close();

            // TO-DO: store the private key in the file PRIVATE_KEY_FILE
            // ...
            File privateFile = new File(PRIVATE_KEY_FILE);
            FileOutputStream outPrivate = new FileOutputStream(privateFile);
            SymmetricCipher cipher = new SymmetricCipher();
            try{
                byte[] pKbyte = cipher.encryptCBC(privateKey.getEncoded(), bytephrase);
                outPrivate.write(pKbyte);
                outPrivate.close();
            }catch (Exception e){
                System.out.println(e);
            }

        } catch (NoSuchAlgorithmException e) {
            System.out.println("Exception: " + e.getMessage());
            System.exit(-1);
        }
    }

    public static byte[] generateByteSeq() throws IllegalArgumentException{
        // pedir passphrase
        System.out.println("Introduce la clave");
        Scanner sc = new Scanner(System.in);
        String phrase = sc.nextLine();

        byte[] bytephrase = phrase.getBytes();
        if (bytephrase.length < 16){
            int n = bytephrase.length;
            byte[] completedbp = new byte[16];
            System.arraycopy(bytephrase, 0, completedbp, 16-n, n);
            return completedbp;
        }
        else if(bytephrase.length > 16){
            throw new IllegalArgumentException("Too long passphrase. Introduce a new one");
        }

        return bytephrase;
    }


    /***********************************************************************************/
    /* Encrypts a plaintext using an RSA public key. */
    /* Arguments: the plaintext and the RSA public key */
    /* Returns a byte array with the ciphertext */
    /***********************************************************************************/
    public byte[] encrypt(byte[] plaintext, PublicKey key) {

        byte[] ciphertext = null;

        try {

            // Gets an RSA cipher object
            final Cipher cipher = Cipher.getInstance(ALGORITHM);

            // TO-DO: initialize the cipher object and use it to encrypt the plaintext
            // ...
            cipher.init(Cipher.ENCRYPT_MODE, key);
            ciphertext = cipher.doFinal(plaintext);

        } catch (Exception e) {
            e.printStackTrace();
        }
        return ciphertext;
    }


    /***********************************************************************************/
    /* Decrypts a ciphertext using an RSA private key. */
    /* Arguments: the ciphertext and the RSA private key */
    /* Returns a byte array with the plaintext */
    /***********************************************************************************/
    public byte[] decrypt(byte[] ciphertext, PrivateKey key) {

        byte[] plaintext = null;

        try {
            // Gets an RSA cipher object
            final Cipher cipher = Cipher.getInstance(ALGORITHM);

            // TO-DO: initialize the cipher object and use it to decrypt the ciphertext
            // ...
            cipher.init(Cipher.DECRYPT_MODE, key);
            plaintext = cipher.doFinal(ciphertext);

        } catch (Exception ex) {
            ex.printStackTrace();
        }

        return plaintext;
    }

    /***********************************************************************************/
    /* Signs a plaintext using an RSA private key. */
    /* Arguments: the plaintext and the RSA private key */
    /* Returns a byte array with the signature */
    /***********************************************************************************/
    public byte[] sign(byte[] plaintext, PrivateKey key) {

        byte[] signedInfo = null;

        try {

            // Gets a Signature object
            Signature signature = Signature.getInstance("SHA1withRSA");

            // TO-DO: initialize the signature oject with the private key
            // ...
            signature.initSign(key);

            // TO-DO: set plaintext as the bytes to be signed
            // ...
            signature.update(plaintext);

            // TO-DO: sign the plaintext and obtain the signature (signedInfo)
            // ...
            signedInfo = signature.sign();


        } catch (Exception ex) {
            ex.printStackTrace();
        }

        return signedInfo;
    }

    /***********************************************************************************/
    /* Verifies a signature over a plaintext */
  /* Arguments: the plaintext, the signature to be verified (signed)
  /* and the RSA public key */
    /* Returns TRUE if the signature was verified, false if not */
    /***********************************************************************************/
    public boolean verify(byte[] plaintext, byte[] signed, PublicKey key) {

        boolean result = false;

        try {

            // Gets a Signature object
            Signature signature = Signature.getInstance("SHA1withRSA");

            // TO-DO: initialize the signature object with the public key
            // ...
            signature.initVerify(key);

            // TO-DO: set plaintext as the bytes to be verified
            // ...
            signature.update(plaintext);

            // TO-DO: verify the signature (signed). Store the outcome in the boolean result
            // ...
            result = signature.verify(signed);

        } catch (Exception ex) {
            ex.printStackTrace();
        }

        return result;
    }

}
