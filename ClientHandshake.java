/**
 * Client side of the handshake.
 */

import java.net.Socket;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.*;
import java.security.cert.*;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
public class ClientHandshake {
    /*
     * The parameters below should be learned by the client
     * through the handshake protocol. 
     */
    
    /* Session host/port  */
    public String sessionHost;
    public int sessionPort;    
    /* Security parameters key/iv should also go here. Fill in! */
    public byte[] sessionKey;
    public byte[] sessionIV;
    /**
     * Run client handshake protocol on a handshake socket. 
     * Here, we do nothing, for now. 
     */ 
    public ClientHandshake(Socket handshakeSocket) throws IOException {
    	
    }
    public void clientHello (Socket socket, String certificatePath){
    	HandshakeMessage clientHelloMessage = new HandshakeMessage();
    	try {
    		X509Certificate clientCertificate = VerifyCertificate.readCertificate(certificatePath);
        	String clientCertificateString = VerifyCertificate.encodeCertificate(clientCertificate);
        	clientHelloMessage.putParameter("MessageType","ClientHello");
        	clientHelloMessage.putParameter("Certificate",clientCertificateString);
        	clientHelloMessage.send(socket);
			Logger.log("ClientHello message sent!");
		} catch (IOException e) {
			e.printStackTrace();
			Logger.log("Fail to send the ClientHello message!");
		} catch (CertificateEncodingException e) {
			e.printStackTrace();
			Logger.log("Fail to read the certificate file!");
		} catch (CertificateException e) {
			e.printStackTrace();
			Logger.log("Fail to encode the certificate!");
		}
    }
    
    public void receiveServerHello (Socket socket, String caPath) {
    	HandshakeMessage serverHelloMessage = new HandshakeMessage();
    	try {
    		serverHelloMessage.recv(socket);
			if (serverHelloMessage.getParameter("MessageType").equals("ServerHello")) {
				String serverCertificateString = serverHelloMessage.getParameter("Certificate");
				X509Certificate serverCertificate = VerifyCertificate.decodeCertificate(serverCertificateString);
				X509Certificate caCertificate = VerifyCertificate.readCertificate(caPath);
				VerifyCertificate.verifyCertificate(caCertificate, serverCertificate); //Ensure the validation
				Logger.log("Server certificate verification successful!");
			} else {
				throw new Exception();
			}
		} catch (IOException e) {
			e.printStackTrace();
			Logger.log("Fail to receive the ServerHello message!");
		} catch (CertificateException e) {
			e.printStackTrace();
			Logger.log("Fail to decode the certificate!");
		} catch (Exception e) {
			e.printStackTrace();
			Logger.log("Fail to verify the server certificate!");
		}
    }
    
    public void forward (Socket socket, String targetHost, String targetPort) {
    	HandshakeMessage forwardMessage = new HandshakeMessage();
    	forwardMessage.putParameter("MessageType","Forward");
    	forwardMessage.putParameter("TargetHost",targetHost);
    	forwardMessage.putParameter("TargetPort",targetPort);
    	try {
			forwardMessage.send(socket);
			Logger.log("Forward message sent!");
		} catch (IOException e) {
			e.printStackTrace();
			Logger.log("Fail to send forward message!");
		}	
    }
    
    public void receiveSession (Socket socket, String privateKeyFile) {
    	HandshakeMessage sessionMessage = new HandshakeMessage();
    	try {
			sessionMessage.recv(socket);
			if (sessionMessage.getParameter("MessageType").equals("Session")) {
				PrivateKey clientPrivateKey = HandshakeCrypto.getPrivateKeyFromKeyFile(privateKeyFile);
				sessionKey = HandshakeCrypto.decrypt(Base64.getDecoder().decode(sessionMessage.getParameter("SessionKey")), clientPrivateKey);
				sessionIV = HandshakeCrypto.decrypt(Base64.getDecoder().decode(sessionMessage.getParameter("SessionIV")), clientPrivateKey);
				sessionHost = sessionMessage.getParameter("SessionHost");
				sessionPort = Integer.parseInt(sessionMessage.getParameter("SessionPort"));
				Logger.log("Session message received!");
			} else {
				throw new Exception();
			}
		} catch (IOException e) {
			e.printStackTrace();
			Logger.log("Fail to receive the session message!");
		} catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
			e.printStackTrace();
		} catch (InvalidKeyException | IllegalBlockSizeException | BadPaddingException
				| NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (Exception e) {
			e.printStackTrace();
		}
    }
}
