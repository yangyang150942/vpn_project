import java.io.*;
import java.security.*;
import java.security.spec.InvalidParameterSpecException;

import javax.crypto.*;
import javax.crypto.spec.*;

public class SessionEncrypter {
	private static String Algorithm_type1 = "AES";
	private static String Algorithm_type2 = "AES/CTR/PKCS5Padding";
	public SecretKey sessionkey;
	public Cipher cipher = null;
	public byte[] IV_byte = null;
	public SessionEncrypter(Integer keylength) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidParameterSpecException {
		KeyGenerator generator;
		generator = KeyGenerator.getInstance(Algorithm_type1); 
		generator.init(keylength); 
		this.sessionkey = generator.generateKey(); 

		this.cipher = Cipher.getInstance(Algorithm_type2);
		this.cipher.init(Cipher.ENCRYPT_MODE, this.sessionkey);
		this.IV_byte = this.cipher.getParameters().getParameterSpec(IvParameterSpec.class).getIV();
	}
	
	public SessionEncrypter(byte[] keybytes, byte[] ivbytes) throws InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchPaddingException {
		this.sessionkey = new SecretKeySpec(keybytes,Algorithm_type1);
		this.IV_byte = ivbytes;
		this.cipher = Cipher.getInstance(Algorithm_type2);
		this.cipher.init(Cipher.ENCRYPT_MODE, this.sessionkey, new IvParameterSpec(ivbytes));
	}
	
	public CipherOutputStream openCipherOutputStream(OutputStream output) {
		return new CipherOutputStream(output,this.cipher);
	}
	public byte[] getKeyBytes() {
		return this.sessionkey.getEncoded();
	}
	public byte[] getIVBytes() {
		return this.IV_byte;
	}
}
