package proj2;

import org.junit.jupiter.api.Assertions;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;

class ARC4CrackerTest {

    @org.junit.jupiter.api.Test
    void noHintCrack() throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        // setup the secret
        byte secretBytes[] = Arrays.copyOf(ARC4Cracker.keyPrefix, 11);
        secretBytes[8] = (byte) 0xd0;
        secretBytes[9] = (byte) 0xff;
        secretBytes[10] = 1;
        SecretKey secretKey = new SecretKeySpec(secretBytes, "ARCFOUR");

        // setup the cipher

        // encrypt and base64 encode
        String plainText = "this is the secret plain text";
        String base64CipherText = Base64.getEncoder().encodeToString(rc4Encrypt(secretKey, plainText.getBytes()));
        String base64KnownString = Base64.getEncoder().encodeToString("secret".getBytes());

        // see if the cracker can give us the answer
        ARC4Cracker cracker = new ARC4Cracker();
        String base64CrackedText = cracker.crack(base64CipherText, base64KnownString);
        Assertions.assertEquals(plainText, new String(Base64.getDecoder().decode(base64CrackedText)));
    }

    private byte[] rc4Encrypt(SecretKey secretKey, byte[] plainText) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher arc4 = Cipher.getInstance("ARCFOUR");
        arc4.init(Cipher.ENCRYPT_MODE, secretKey);
        return arc4.doFinal(plainText);
    }

    @org.junit.jupiter.api.Test
    void hintedCrack() throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        // setup the secret
        byte secretBytes[] = Arrays.copyOf(ARC4Cracker.keyPrefix, 11);
        secretBytes[8] = (byte) 0xbe;
        secretBytes[9] = (byte) 0xef;
        secretBytes[10] = 2;
        SecretKey secretKey = new SecretKeySpec(secretBytes, "ARCFOUR");

        ARC4Cracker cracker = new ARC4Cracker();

        byte plainHint1[] = "the hint that only the last part was broken".getBytes();
        byte cipherHint1[] = rc4Encrypt(secretKey, plainHint1);
        cracker.crackedText(Base64.getEncoder().encodeToString(Arrays.copyOfRange(cipherHint1, 10, 30)),
                Base64.getEncoder().encodeToString(Arrays.copyOfRange(plainHint1, 10, 30)), 10);

        byte plainHint2[] = "we figured out this message".getBytes();
        byte cipherHint2[] = rc4Encrypt(secretKey, plainHint2);
        cracker.crackedText(Base64.getEncoder().encodeToString(Arrays.copyOfRange(cipherHint2, 0, 15)),
                Base64.getEncoder().encodeToString(Arrays.copyOfRange(plainHint2, 0, 15)), 0);

        // encrypt and base64 encode
        String plainText = "this is the secret with hints";
        String base64CipherText = Base64.getEncoder().encodeToString(rc4Encrypt(secretKey, plainText.getBytes()));
        String base64KnownString = Base64.getEncoder().encodeToString("hint".getBytes());

        // see if the cracker can give us the answer
        String base64CrackedText = cracker.crack(base64CipherText, base64KnownString);
        Assertions.assertEquals(plainText, new String(Base64.getDecoder().decode(base64CrackedText)));
    }

    @org.junit.jupiter.api.Test
    void noHintCrack2() throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        // setup the secret
        byte secretBytes[] = Arrays.copyOf(ARC4Cracker.keyPrefix, 11);
        secretBytes[8] = (byte) 0xbe;
        secretBytes[9] = (byte) 0xef;
        secretBytes[10] = (byte) 2;
        SecretKey secretKey = new SecretKeySpec(secretBytes, "ARCFOUR");

        // setup the cipher

        ARC4Cracker cracker = new ARC4Cracker();

        byte plainHint1[] = "pump it up prime 1".getBytes();
        byte cipherHint1[] = rc4Encrypt(secretKey, plainHint1);
        cracker.crackedText(Base64.getEncoder().encodeToString(Arrays.copyOfRange(cipherHint1, 17,18)),
                Base64.getEncoder().encodeToString(Arrays.copyOfRange(plainHint1, 17, 18)), 17);

        byte plainHint2[] = "we figured out this message".getBytes();
        byte cipherHint2[] = rc4Encrypt(secretKey, plainHint2);
        cracker.crackedText(Base64.getEncoder().encodeToString(Arrays.copyOfRange(cipherHint2, 0, 15)),
                Base64.getEncoder().encodeToString(Arrays.copyOfRange(plainHint2, 0, 15)), 0);

        // encrypt and base64 encode
        String plainText = "Pump It Up Prime 2";
        String base64CipherText = Base64.getEncoder().encodeToString(rc4Encrypt(secretKey, plainText.getBytes()));
        String base64KnownString = Base64.getEncoder().encodeToString("Prime".getBytes());

        // see if the cracker can give us the answer
        String base64CrackedText = cracker.crack(base64CipherText, base64KnownString);
        Assertions.assertEquals(plainText, new String(Base64.getDecoder().decode(base64CrackedText)));
    }

}