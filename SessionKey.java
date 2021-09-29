import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.KeyGenerator;
import java.security.NoSuchAlgorithmException;

public class SessionKey {

	private static String Algorithm_type = "AES";
	public SecretKey sessionkey;
	private byte[] sessionkey_byte;
	
	//create session key according to indicated length
	public SessionKey(Integer keylength) {
		KeyGenerator generator;
		try {
			generator = KeyGenerator.getInstance(Algorithm_type); 
			generator.init(keylength); 
			this.sessionkey = generator.generateKey(); 
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
	}
	
	//create session key from existing byte array
	public SessionKey(byte[] keybytes) {
		this.sessionkey = new SecretKeySpec(keybytes,Algorithm_type);
	}
	
	public SecretKey getSecretKey() {
		return this.sessionkey;
	}
	
	public byte[] getKeyBytes() {
		this.sessionkey_byte = this.sessionkey.getEncoded();
		return this.sessionkey_byte;
	}
}
