package proj2;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.*;

/**
 * @author nhuluong
 *
 * cracks weakened ARC4 keys. we know all cipher text has been encrypted with
 * a 11 byte ARC4 key. we also know that the first 8 bytes of the key are:
 * 0x1337d00d1550c001
 *
 * each instance of this class represents a ARC4 key to be discovered. all hints
 * about cracked text and requests to crack will be for cipher text encrypted
 * with the same key.
 */
public class ARC4Cracker {
    /**
     * the know prefix. (we just need to discover the remaining 3 bytes)
     */
    static public byte keyPrefix[] = { 0x13, 0x37, (byte)0xd0, 0x0d, 0x15, 0x50, (byte)0xc0, 0x01};
    static private Map<int[], byte[]> keyStreamMap = new HashMap<>();

    /**
     * this method provides a hint of known plaintext, and the corresponding cipherText
     * @param base64CipherText base64 encoded known cipher text from
     * @param base64PlainText base64 encoded known plain text from
     * @param position the position in the stream where the text was known
     */
    public void crackedText(String base64CipherText, String base64PlainText, int position) {
        byte[] cipherText = Base64.getDecoder().decode(base64CipherText);
        byte[] plainText = Base64.getDecoder().decode(base64PlainText);
        byte[] keyStream = new byte[cipherText.length];
        //Get the keyStream
        for (int i = 0; i < cipherText.length; i++) {
            keyStream[i] = (byte) (plainText[i] ^ cipherText[i]);
        }
        int[] pos = { position, position + plainText.length};
        keyStreamMap.put(pos,keyStream);
    }

    /**
     * the method will crack cipher text by searching for the correct plain text containing
     * the known string
     * @param base64CipherText base64 encoded cipher text to crack
     * @param base64KnownText a base64 encoded string that is know to exist in the plain text
     * @return the base64 encoded plain text or null if couldn't crack
     */
    public String crack(String base64CipherText, String base64KnownText) throws  NoSuchAlgorithmException, NoSuchPaddingException,InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        byte[] cipher = Base64.getDecoder().decode(base64CipherText);
        String known = new String(Base64.getDecoder().decode(base64KnownText));
        boolean missing = false;
        if(!keyStreamMap.isEmpty()){
            byte[] keyStream = new byte[cipher.length];
            for(int i = 0; i < keyStream.length;i++){
                keyStream[i] = 0;
            }
            for(Map.Entry<int[], byte[]> entry : keyStreamMap.entrySet()){
                int start = entry.getKey()[0];
                int end = entry.getKey()[1];
                byte[] stream = entry.getValue();
                for(int i = start; i < keyStream.length && i-start < stream.length; i++) {
                    keyStream[i] = stream[i-start];
                }
            }
            for(int i = 0; i < keyStream.length;i++){
                if(keyStream[i] == 0){
                    missing = true;
                }
            }
            if(!missing){
                byte[] result = new byte[cipher.length];
                for(int i = 0; i < cipher.length; i++){
                    result[i] = (byte) (cipher[i] ^ keyStream[i]);
                }
                return Base64.getEncoder().encodeToString(result);
            }
        }
        Cipher arc4 = Cipher.getInstance("ARCFOUR");
        byte secretBytes[] = Arrays.copyOf(ARC4Cracker.keyPrefix, 11);
        for (int i = 0; i < 256; i++) {
            for (int j = 0; j < 256; j++) {
                for (int k = 0; k < 256; k++) {
                    secretBytes[8] = (byte) i;
                    secretBytes[9] = (byte) j;
                    secretBytes[10] = (byte) k;
                    SecretKey secretKey = new SecretKeySpec(secretBytes, "ARCFOUR");
                    arc4.init(Cipher.DECRYPT_MODE, secretKey);
                    if (new String(arc4.doFinal(cipher)).contains(known)) {
                        return Base64.getEncoder().encodeToString(arc4.doFinal(cipher));
                    }
                }
            }
        }
        return null;
    }
}
