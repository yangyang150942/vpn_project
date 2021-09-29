import java.io.*;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;

public class SessionDecrypter {
	private static String Algorithm_type1 = "AES";
	private static String Algorithm_type2 = "AES/CTR/PKCS5Padding";
	public SecretKey sessionkey;
	public Cipher cipher = null;
	public IvParameterSpec IV = null;
	
	public SessionDecrypter(byte[] keybytes, byte[] ivbytes) throws InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchPaddingException {
		this.sessionkey = new SecretKeySpec(keybytes,Algorithm_type1);
		this.IV = new IvParameterSpec(ivbytes);
		this.cipher = Cipher.getInstance(Algorithm_type2);
		this.cipher.init(Cipher.DECRYPT_MODE, this.sessionkey, this.IV);
	}
	
	CipherInputStream openCipherInputStream(InputStream input) {
		return new CipherInputStream(input, this.cipher);
	}
}
