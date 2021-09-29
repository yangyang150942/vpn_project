import java.io.*;
import java.security.*;
import java.security.cert.*;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Base64;
import java.util.Date;

public class VerifyCertificate {
	public static void main(String[] args) throws CertificateException, FileNotFoundException {
		X509Certificate CA = readCertificate(args[0]);
		X509Certificate user = readCertificate(args[1]);
		verifyCertificate(CA,user);
	}
	
	public static void verifyCertificate(X509Certificate CA, X509Certificate user) {		
		boolean flag = false;
		Date date = null;
        SimpleDateFormat dateformat = new SimpleDateFormat("yyyy-MM-dd"); 
        try {
			date = dateformat.parse("2021-01-18");
		} catch (ParseException e2) {
			// TODO Auto-generated catch block
			e2.printStackTrace();
		}
        
		System.out.println(CA.getSubjectX500Principal());
		System.out.println(user.getSubjectX500Principal());
		try {
			CA.verify(CA.getPublicKey());
			CA.checkValidity(date);
			flag = true;
		} catch (CertificateExpiredException | CertificateNotYetValidException e1) {
			System.out.println("Fail.\nCA is not valid.");
		} catch (CertificateException | InvalidKeyException | NoSuchAlgorithmException | NoSuchProviderException | SignatureException e) {
			System.out.println("Fail.\nCA verification failed.");
		} 
	
		try {
			user.verify(CA.getPublicKey());
			user.checkValidity(date);
			if (flag) {
				System.out.println("Pass");
			}
		} catch (CertificateExpiredException | CertificateNotYetValidException e1) {
			System.out.println("Fail.\nCA is not valid.");
		} catch (CertificateException | InvalidKeyException | NoSuchAlgorithmException | NoSuchProviderException | SignatureException e) {
			System.out.println("Fail.\nCA verification failed.");
		} 
	}
	
	public static X509Certificate readCertificate (String certificatePath) throws CertificateException, FileNotFoundException {
		CertificateFactory certificateFac = CertificateFactory.getInstance("X.509");
		FileInputStream certificateFile = new FileInputStream (certificatePath);
		X509Certificate certificate = (X509Certificate) certificateFac.generateCertificate(certificateFile);
		return certificate;
	}
	public static String encodeCertificate (X509Certificate certificate) throws CertificateEncodingException {
		return Base64.getEncoder().encodeToString(certificate.getEncoded());
	}
	public static X509Certificate decodeCertificate(String certificateString) throws CertificateException {
	    byte[] certificateByte = Base64.getDecoder().decode(certificateString);
	    CertificateFactory certificateFac = CertificateFactory.getInstance("X.509");
	    InputStream inputStream = new ByteArrayInputStream(certificateByte);
	    return  (X509Certificate) certificateFac.generateCertificate(inputStream);
	 }
}
