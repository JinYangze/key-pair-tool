package gold.hibiscus;

import gold.hibiscus.util.HexUtils;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

public class KeyPairTool {
    public static final int KEY_SIZE_2048 = 2048;
    public static final int KEY_SIZE_3072 = 3072;
    public static final String KEY_ALGORITHM_RSA = "RSA";

    public static final String PUBLIC_KEY = "publicKey";
    public static final String PRIVATE_KEY = "privateKey";

    public void generateKeyFiles(String publicKeyPath, String privateKeyPath) throws NoSuchAlgorithmException, IOException {
        generateKeyFiles(publicKeyPath, privateKeyPath, KeySaveMethod.BASE64);
    }

    public void generateKeyFiles(String publicKeyPath, String privateKeyPath, KeySaveMethod method) throws NoSuchAlgorithmException, IOException {
        generateKeyFiles(publicKeyPath, privateKeyPath, KEY_ALGORITHM_RSA, KEY_SIZE_3072, method);
    }

    public void generateKeyFiles(String publicKeyPath, String privateKeyPath, String algorithm, int keySize, KeySaveMethod method) throws NoSuchAlgorithmException, IOException {
        Map<String, byte[]> keyMap = generateKeys(algorithm, keySize);
        String publicKey = getKeyString(keyMap.get(PUBLIC_KEY), method);
        String privateKey = getKeyString(keyMap.get(PRIVATE_KEY), method);
        Files.writeString(Paths.get(publicKeyPath), publicKey);
        Files.writeString(Paths.get(privateKeyPath), privateKey);
    }

    public Map<String, byte[]> generateKeys() throws NoSuchAlgorithmException {
        return generateKeys(KEY_ALGORITHM_RSA, KEY_SIZE_3072);
    }

    public Map<String, byte[]> generateKeys(String algorithm, int keySize) throws NoSuchAlgorithmException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance(algorithm);
        generator.initialize(keySize);
        KeyPair keyPair = generator.generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();
        Map<String, byte[]> keyMap = new HashMap<>();
        keyMap.put(PUBLIC_KEY, publicKey.getEncoded());
        keyMap.put(PRIVATE_KEY, privateKey.getEncoded());
        return keyMap;
    }

    public PublicKey getPublicKey(byte[] encoding) throws NoSuchAlgorithmException, InvalidKeySpecException {
        return getPublicKey(encoding, KEY_ALGORITHM_RSA);
    }

    public PublicKey getPublicKey(byte[] encoding, String algorithm) throws NoSuchAlgorithmException, InvalidKeySpecException {
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encoding);
        KeyFactory factory = KeyFactory.getInstance(algorithm);
        return factory.generatePublic(keySpec);
    }

    public PrivateKey getPrivateKey(byte[] encoding) throws NoSuchAlgorithmException, InvalidKeySpecException {
        return getPrivateKey(encoding, KEY_ALGORITHM_RSA);
    }

    public PrivateKey getPrivateKey(byte[] encoding, String algorithm) throws NoSuchAlgorithmException, InvalidKeySpecException {
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoding);
        KeyFactory factory = KeyFactory.getInstance(algorithm);
        return factory.generatePrivate(keySpec);
    }

    private String getKeyString(byte[] encoding, KeySaveMethod method) {
        return switch (method) {
            case HEX -> HexUtils.toHexString(encoding);
            case BASE64 -> Base64.getEncoder().encodeToString(encoding);
        };
    }
}
