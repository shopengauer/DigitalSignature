package digitalsignature;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;


public class Main {

    public static void main(String[] args) throws SignatureException {
        System.out.println("Hello World!");
        byte[] inArr = {1,2,3,4,5,6,7,8,9,0};
        byte[] inArr2 = {1,2,3,4,5,6,7,8,9,0,7};
        byte[] outArr = null;

        KeyPairGenerator keyGen = null;
        SecureRandom random = null;
        Signature dsa = null;
        KeyFactory keyFactory = null;
        try {
            keyGen = KeyPairGenerator.getInstance("DSA", "SUN");
            random = SecureRandom.getInstance("SHA1PRNG", "SUN");
            dsa = Signature.getInstance("SHA1withDSA", "SUN");
            keyFactory = KeyFactory.getInstance("DSA", "SUN");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        }


        keyGen.initialize(1024, random);
        KeyPair pair = keyGen.generateKeyPair();
        PrivateKey priv = pair.getPrivate();
        PublicKey pub = pair.getPublic();

        try {
            dsa.initSign(priv);
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }

        try {
           dsa.update(inArr);
        } catch (SignatureException e) {
            e.printStackTrace();
        }

        try {
            outArr = dsa.sign();
        } catch (SignatureException e) {
            e.printStackTrace();
        }

        for (byte b : inArr) {
            System.out.println(b);
        }


        for (byte b : outArr) {
            System.out.println(b);
        }

        byte[] encKey = pub.getEncoded();
        X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(encKey);

        PublicKey pubKey = null;
        try {
            pubKey =
                    keyFactory.generatePublic(pubKeySpec);
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }

        try {
            dsa.initVerify(pubKey);
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }


        try {
            dsa.update(inArr2);
        } catch (SignatureException e) {
            e.printStackTrace();
        }

        boolean verifies = dsa.verify(outArr);
        System.out.println(verifies);
    }
}
