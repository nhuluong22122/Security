package proj3;


import com.sun.xml.internal.rngom.parse.host.Base;
import sun.misc.BASE64Decoder;
import sun.security.util.DerInputStream;
import sun.security.util.DerValue;

import java.io.File;
import java.io.IOException;
import java.lang.reflect.Array;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;

/**
 * @author nhuluong
 * Sign and validate signature using private and public key
 */
public class BlobSigner {
    /**
     * generate a signature file (dstSignatureFile) for fileToSign using
     * sshPrivateKeyFile.
     *
     * @param fileToSign        the file containing the data to be signed.
     * @param sshPrivateKeyFile the ssh private key file with the signing key
     *                          to use.
     * @param dstSignatureFile  the file to write the generated signature to.
     *                          the signature will be base64 encoded.
     */
    public static void signFile(
            File fileToSign, File sshPrivateKeyFile, File dstSignatureFile
    ) throws Exception {
        Signature sha256Signature = Signature.getInstance("SHA256withRSA");
        PrivateKey privateKey = pemFileLoadPrivateKeyPkcs1OrPkcs8Encoded(sshPrivateKeyFile);
        byte[] data = Files.readAllBytes(fileToSign.toPath());
        sha256Signature.initSign(privateKey);
        sha256Signature.update(data);
        byte[] signed = sha256Signature.sign();
        Files.write(dstSignatureFile.toPath(), Base64.getEncoder().encode(signed));

    }

    /**
     * validate the signature file (signatureFile) corresponding to
     * signedFile using the public key in sshPublicKeyFile.
     *
     * @param signedFile       the file containing the data that was signed.
     * @param sshPublicKeyFile the file containing the public key corresponds
     *                         to the private key that was used to sign
     *                         signedFile.
     * @param signatureFile    the base64 encoded signature generated with the
     *                         private key that corresponds to sshPublicKeyFile
     *                         over the data in the signedFile.
     * @return true if the signature is valid.
     */
    public static boolean validateSignature(
            File signedFile, File sshPublicKeyFile, File signatureFile
    ) throws Exception {
        Signature sha256Signature = Signature.getInstance("SHA256withRSA");
        PublicKey publicKey = parsePublicKey(sshPublicKeyFile);
        byte[] data = Files.readAllBytes(signedFile.toPath());
        sha256Signature.initVerify(publicKey);
        sha256Signature.update(data);
        byte[] signature = Files.readAllBytes(signatureFile.toPath());
        return sha256Signature.verify(Base64.getDecoder().decode(signature));
    }

    /**
     * Adapted from https://stackoverflow.com/a/30929175 - Yuri G.
     **/
    private static PrivateKey pemFileLoadPrivateKeyPkcs1OrPkcs8Encoded(File pemFileName) throws GeneralSecurityException, IOException {
        // PKCS#8 format
        final String PEM_PRIVATE_START = "-----BEGIN PRIVATE KEY-----";
        final String PEM_PRIVATE_END = "-----END PRIVATE KEY-----";

        // PKCS#1 format
        final String PEM_RSA_PRIVATE_START = "-----BEGIN RSA PRIVATE KEY-----";
        final String PEM_RSA_PRIVATE_END = "-----END RSA PRIVATE KEY-----";

        Path path = Paths.get(pemFileName.getAbsolutePath());

        String privateKeyPem = new String(Files.readAllBytes(path));

        if (privateKeyPem.indexOf(PEM_PRIVATE_START) != -1) { // PKCS#8 format
            privateKeyPem = privateKeyPem.replace(PEM_PRIVATE_START, "").replace(PEM_PRIVATE_END, "");
            privateKeyPem = privateKeyPem.replaceAll("\\s", "");

            byte[] pkcs8EncodedKey = Base64.getDecoder().decode(privateKeyPem);

            KeyFactory factory = KeyFactory.getInstance("RSA");
            return factory.generatePrivate(new PKCS8EncodedKeySpec(pkcs8EncodedKey));

        } else if (privateKeyPem.indexOf(PEM_RSA_PRIVATE_START) != -1) {  // PKCS#1 format
            privateKeyPem = privateKeyPem.replace(PEM_RSA_PRIVATE_START, "").replace(PEM_RSA_PRIVATE_END, "");
            privateKeyPem = privateKeyPem.replaceAll("\\s", "");

            DerInputStream derReader = new DerInputStream(Base64.getDecoder().decode(privateKeyPem));

            DerValue[] seq = derReader.getSequence(0);

            if (seq.length < 9) {
                throw new GeneralSecurityException("Could not parse a PKCS1 private key.");
            }

            // skip version seq[0];
            BigInteger modulus = seq[1].getBigInteger();
            BigInteger publicExp = seq[2].getBigInteger();
            BigInteger privateExp = seq[3].getBigInteger();
            BigInteger prime1 = seq[4].getBigInteger();
            BigInteger prime2 = seq[5].getBigInteger();
            BigInteger exp1 = seq[6].getBigInteger();
            BigInteger exp2 = seq[7].getBigInteger();
            BigInteger crtCoef = seq[8].getBigInteger();

            RSAPrivateCrtKeySpec keySpec = new RSAPrivateCrtKeySpec(modulus, publicExp, privateExp, prime1, prime2, exp1, exp2, crtCoef);

            KeyFactory factory = KeyFactory.getInstance("RSA");
            return factory.generatePrivate(keySpec);
        }

        throw new GeneralSecurityException("Not supported format of a private key");
    }

    /**
     * Parse the public key file and return the Public Key
     * @param pemFileName public key file
     * @return Public Key Object
     * @throws GeneralSecurityException
     * @throws IOException
     */
    private static PublicKey parsePublicKey(File pemFileName) throws GeneralSecurityException, IOException {
        Path path = Paths.get(pemFileName.getAbsolutePath());
        String publicKeyPem = new String(Files.readAllBytes(path));
        String[] fields =  publicKeyPem.split(" ");
        byte[] decoded = Base64.getDecoder().decode(fields[1]);
        //three length encoded records
        ArrayList<byte[]> arr = decodeLVBytes(decoded);

        BigInteger exponent = new BigInteger(arr.get(1));
        BigInteger modulus = new BigInteger(arr.get(2));

        RSAPublicKeySpec keySpec = new RSAPublicKeySpec(modulus, exponent);
        KeyFactory factory = KeyFactory.getInstance("RSA");
        return factory.generatePublic(keySpec);
    }


    /**
     * Adapted from Ben to parse the middle section of public key file
     **/
    private static ArrayList<byte[]> decodeLVBytes(byte toDecode[]) {
        ArrayList<byte[]> list = new ArrayList<>();
        ByteBuffer bb = ByteBuffer.wrap(toDecode);
        while (bb.position() < bb.limit()) {
            int len = bb.getInt();
            byte bytes[] = new byte[len];
            bb.get(bytes);
            list.add(bytes);
        }
        return list;
    }
}
