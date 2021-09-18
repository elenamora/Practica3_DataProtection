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

        byte padding = (byte)0;
        int lackingBlocks = 0;

        // Generate the plaintext with padding
        lackingBlocks = (input.length % 16);
        if(input.length < 16)
            lackingBlocks = 16 - lackingBlocks;

        if(lackingBlocks==0){
            lackingBlocks = 16;
        }

        padding = (byte)lackingBlocks;

        byte[] paddedInput = new byte[input.length+padding];
        for(int i = 0; i < lackingBlocks; i++){
            paddedInput[paddedInput.length-1-i] = padding;
        }

        // Generate the ciphertext
        byte[] cypheredBlock = iv;
        byte[] preCypheredBlock = new byte[16];
        byte[] cypheredOutput = new byte[paddedInput.length];
        s = new SymmetricEncryption(byteKey);

        for(int i = 0; i < paddedInput.length/16; i=i+16) {
            for (int j = 0; j < 16; j++) {
                preCypheredBlock[j] = (byte)(paddedInput[i + j] ^ cypheredBlock[j]);
            }
            cypheredBlock = s.encryptBlock(preCypheredBlock);

            for (int j = 0; j < 16; j++) {
                cypheredOutput[i+j] = cypheredBlock[j];
            }
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

        for(int i = 0; i < input.length/16; i += 16){
            // obtain block to decrypt
            System.arraycopy(input, i, encryptedBlock, 0, 16);

            // decrypt block
            decryptedBlock = d.decryptBlock(encryptedBlock);

            // apply xor operation with iv or previous encrypted block
            // include resulting block into decrypted text
            for (int j = 0; j < 15; j++) {
                decryptedText[j + i] = (byte) (decryptedBlock[j] ^ vector[j]);
            }
            vector = encryptedBlock;
        }

        // Eliminate the padding
        boolean hasPadding = false;
        int lastBlockValue = decryptedText[decryptedText.length-1];

        // check if last block has a possible padding value
        if(lastBlockValue <= 16 && lastBlockValue >= 1){
            // iterative checking of last blocks
            for(int i = 0; i < decryptedText.length; i++){
                if((int)decryptedText[decryptedText.length-1-i] == lastBlockValue){
                    continue;
                }
                else{
                    if (i == lastBlockValue) {
                        hasPadding = true;
                    }
                    break;
                }
            }
        }
        if (hasPadding){
            for (int i = 0; i < lastBlockValue; i++)
                decryptedText = Arrays.copyOf(decryptedText, decryptedText.length-1);
        }

        return decryptedText;
    }
}
