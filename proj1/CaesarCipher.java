import static java.lang.Math.floorMod;
/**
 * @author nhuluong
 * implement a ceaser cipher that operates on ASCII characters a-z and A-Z
 * only. all other characters are passed through unchanged. the character
 * case is preserved.
 *
 * for example, if the rotation key is 23 and the plain text is "Hi there",
 * the resulting cipher text will be "Ef qebob".
 */
public class CaesarCipher {
    private int shift;
    /**
     * create a cipher with the given rotation. (note that it may be any integer.
     * @param shift the secret amount of shift to use when encoding
     */
    public CaesarCipher(int shift) {
        this.shift = shift;
    }

    /**
     * return the encrypted version of the plainText based on the shift.
     * @param plainText the text to encrypt. the data will not be changed by this function.
     * @return the cipherText of the plainText.
     */
    public byte[] encrypt(byte[] plainText) {
        byte result[] = new byte[plainText.length];
        if(shift != 0 && plainText.length != 0 && 26 - shift != 0){
            for(int i = 0; i < plainText.length; i++){
                //upper-case
                //65 is the first upper-case letter
                if(plainText[i] < 91 && plainText[i] > 64) {
                    result[i] = (byte) (floorMod(plainText[i] + shift - 65,26) + 65) ;
                }
                //lower-case
                //97 is the first lower-case letter
                else if (plainText[i] < 123 && plainText[i] > 96){
                    result[i] = (byte) (floorMod(plainText[i] + shift - 97,26) + 97) ;
                }
                else {
                    result[i] = plainText[i];
                }
            }
        }
        else {
            result = plainText;
        }
        return result;
    }

    /**
     * return the decrypted version of the cipherText based on the shift.
     * @param cipherText the text to encrypt. the data will not be changed by this function.
     * @return the plainText of the plainText.
     */
    public byte[] decrypt(byte[] cipherText) {
        byte result[] = new byte[cipherText.length];
        if(shift != 0 && cipherText.length != 0 && 26 - shift != 0){
            for(int i = 0; i < cipherText.length; i++){
                //upper-case
                //65 is the first upper-case letter
                if(cipherText[i] < 91 && cipherText[i] > 64) {
                    result[i] = (byte) (floorMod(cipherText[i] - shift  - 65,26) + 65) ;
                }
                //lower-case
                //97 is the first lower-case letter
                else if (cipherText[i] < 123 && cipherText[i] > 96){
                    result[i] = (byte) (floorMod(cipherText[i] - shift  - 97,26) + 97);
                }
                else {
                    result[i] = cipherText[i];
                }
            }
        }
        else {
            result = cipherText;
        }
        return result;
    }
}
