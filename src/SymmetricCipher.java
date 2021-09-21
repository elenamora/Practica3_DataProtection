import java.awt.*;
import java.io.FileDescriptor;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.NoSuchAlgorithmException;
import javax.crypto.*;
import java.security.InvalidKeyException;

import java.util.*;

public class SymmetricCipher {
    byte[] byteKey;
    SymmetricEncryption s;
    SymmetricEncryption d;

    // Initialization Vector (fixed)

    byte[] iv = new byte[] { (byte)49, (byte)50, (byte)51, (byte)52, (byte)53, (byte)54,
            (byte)55, (byte)56, (byte)57, (byte)48, (byte)49, (byte)50, (byte)51, (byte)52,
            (byte)53, (byte)54};

    /*************************************************************************************/
    /* Constructor method */
    /*************************************************************************************/
    public void SymmetricCipher() {
    }

    /*************************************************************************************/
    /* Method to encrypt using AES/CBC/PKCS5 */
    /*************************************************************************************/
    public byte[] encryptCBC (byte[] input, byte[] byteKey) throws Exception {

        byte padding;
        int lackingBlocks;

        // Generate the plaintext with padding
        lackingBlocks = 16 - (input.length % 16);

        padding = (byte)lackingBlocks;

        byte[] paddedInput = Arrays.copyOf(input,input.length+padding);
        for(int i = 0; i < lackingBlocks; i++){
            paddedInput[paddedInput.length-1-i] = padding;
        }

        // Generate the ciphertext
        byte[] cypheredBlock = iv;
        byte[] preCypheredBlock = new byte[16];
        byte[] cypheredOutput = new byte[paddedInput.length];
        s = new SymmetricEncryption(byteKey);

        for(int i = 0; i < paddedInput.length-1; i=i+16) {
            for (int j = 0; (j < 16) && (j+i) < paddedInput.length; j++) {
                preCypheredBlock[j] = (byte)(paddedInput[i + j] ^ cypheredBlock[j]);
            }
            cypheredBlock = s.encryptBlock(preCypheredBlock);

            System.arraycopy(cypheredBlock, 0, cypheredOutput, i, 16);
        }
        return cypheredOutput;
    }

    /*************************************************************************************/
    /* Method to decrypt using AES/CBC/PKCS5 */
    /*************************************************************************************/


    public byte[] decryptCBC (byte[] input, byte[] byteKey) throws Exception {

        // Generate the plaintex
        byte [] decryptedText = new byte[input.length];
        d = new SymmetricEncryption(byteKey);
        byte[] vector = iv;
        byte[] encryptedBlock = new byte[16];
        byte[] decryptedBlock;

        for(int i = 0; i < input.length; i += 16){
            // obtain block to decrypt
            System.arraycopy(input, i, encryptedBlock, 0, 16);

            // decrypt block
            decryptedBlock = d.decryptBlock(encryptedBlock);

            // apply xor operation with iv or previous encrypted block
            // include resulting block into decrypted text
            for (int j = 0; j < 16; j++) {
                decryptedText[j + i] = (byte) (decryptedBlock[j] ^ vector[j]);
            }
            vector = encryptedBlock.clone();
        }

        // Eliminate the padding
        int lastBlockValue = decryptedText[decryptedText.length-1];

        for (int i = 0; i < lastBlockValue; i++)
            decryptedText = Arrays.copyOf(decryptedText, decryptedText.length-1);

        return decryptedText;
    }
}
