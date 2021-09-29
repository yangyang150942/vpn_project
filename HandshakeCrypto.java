import java.io.*;
import java.nio.file.*;
import java.security.*;
import java.security.cert.*;
import java.security.spec.*;
import javax.crypto.*;

public class HandshakeCrypto {
	private static final String Algorithm_type = "RSA";
	public static byte[] encrypt(byte[] plaintext, Key key) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException {
		Cipher cipher = Cipher.getInstance(Algorithm_type);
		cipher.init(Cipher.ENCRYPT_MODE, key);
		byte[] ciphertext_byte = cipher.doFinal(plaintext);
		return ciphertext_byte;
	}
	
	public static byte[] decrypt(byte[] ciphertext, Key key) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException {
		Cipher cipher = Cipher.getInstance(Algorithm_type);
		cipher.init(Cipher.DECRYPT_MODE, key);
		byte[] plaintext_byte = cipher.doFinal(ciphertext);
		return plaintext_byte;
	}
	
	public static PublicKey getPublicKeyFromCertFile(String certfile) throws FileNotFoundException, CertificateException {   
		FileInputStream certfile_input = new FileInputStream(certfile);
		CertificateFactory certificate_fac = CertificateFactory.getInstance("X.509");
		X509Certificate certificate = (X509Certificate)certificate_fac.generateCertificate(certfile_input);
		PublicKey publicKey = certificate.getPublicKey();
		return publicKey;
	}
	
	public static PrivateKey getPrivateKeyFromKeyFile(String keyfile) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {  
		Path keyfile_path = Paths.get(keyfile);
		byte[] privateKey_byte = Files.readAllBytes(keyfile_path);
		PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKey_byte);
		KeyFactory privateKey_fac = KeyFactory.getInstance(Algorithm_type);
		PrivateKey privateKey = privateKey_fac.generatePrivate(keySpec);
		return privateKey;
	}
}
