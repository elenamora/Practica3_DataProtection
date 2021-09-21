import java.util.Arrays;
import java.nio.charset.StandardCharsets;

public class Test {

    public static void main(String[] args) throws Exception {
        String plainText = "Since the symmetric key algorithms, based on the concept of a block cipher, allow you to\n" +
                "encrypt blocks of plaintext of fixed size, it will be necessary to apply some padding technique\n" +
                "to the input file to make its length be a multiple of the size of the block";
        byte[] bytedText = plainText.getBytes();
        System.out.println(Arrays.toString(bytedText));
        byte[] key = new byte[16];
        SymmetricCipher cipher = new SymmetricCipher();
        byte[] encryptedText = cipher.encryptCBC(bytedText, key);
        System.out.println(Arrays.toString(encryptedText));
        byte[] decryptedText = cipher.decryptCBC(encryptedText, key);
        System.out.println(Arrays.toString(decryptedText));
        String finalText = new String(decryptedText, StandardCharsets.UTF_8);
        System.out.println(finalText);
    }
}
