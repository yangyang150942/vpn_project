/**
 * Server side of the handshake.
 */

import java.net.InetAddress;
import java.net.Socket;
import java.security.*;
import java.security.cert.*;
import java.security.spec.InvalidParameterSpecException;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import java.net.ServerSocket;
import java.io.IOException;

public class ServerHandshake {
    /*
     * The parameters below should be learned by the server
     * through the handshake protocol. 
     */
    
    /* Session host/port, and the corresponding ServerSocket  */
    public ServerSocket sessionSocket;
    public static String sessionHost;
    public static int sessionPort;    

    /* The final destination -- simulate handshake with constants */
    public String targetHost;
    public int targetPort;

    /* Security parameters key/iv should also go here. Fill in! */
    public byte[] sessionKey;
    public byte[] sessionIV;
    private X509Certificate clientCertificate;
    /**
     * Run server handshake protocol on a handshake socket. 
     * Here, we simulate the handshake by just creating a new socket
     * with a preassigned port number for the session.
     */ 
    public ServerHandshake(Socket handshakeSocket) throws IOException {
        sessionSocket = new ServerSocket(12345);
        sessionHost = sessionSocket.getInetAddress().getHostName();
        sessionPort = sessionSocket.getLocalPort();
    }
    
    public void receiveClientHello (Socket socket, String caPath) {
    	HandshakeMessage clientHelloMessage = new HandshakeMessage();
    	try {
    		clientHelloMessage.recv(socket);
			if (clientHelloMessage.getParameter("MessageType").equals("ClientHello")) {
				String clientCertificateString = clientHelloMessage.getParameter("Certificate");
				clientCertificate = VerifyCertificate.decodeCertificate(clientCertificateString);
				X509Certificate caCertificate = VerifyCertificate.readCertificate(caPath);
				VerifyCertificate.verifyCertificate(caCertificate, clientCertificate); ////Ensure the validation
				Logger.log("Client certificate verification successful!");
			} else {
				throw new Exception();
			}
		} catch (IOException e) {
			e.printStackTrace();
			Logger.log("Fail to receive the ClientHello message!");
		} catch (CertificateException e) {
			e.printStackTrace();
			Logger.log("Fail to decode the certificate!");
		} catch (Exception e) {
			e.printStackTrace();
			Logger.log("Fail to verify the Client certificate!");
		}
    }
    
    public void serverHello (Socket socket, String certificatePath) {
    	HandshakeMessage serverHelloMessage = new HandshakeMessage();
    	try {
    		X509Certificate serverCertificate = VerifyCertificate.readCertificate(certificatePath);
        	String serverCertificateString = VerifyCertificate.encodeCertificate(serverCertificate);
        	serverHelloMessage.putParameter("MessageType","ServerHello");
        	serverHelloMessage.putParameter("Certificate",serverCertificateString);
        	serverHelloMessage.send(socket);
			Logger.log("ServerHello message sent!");
		} catch (IOException e) {
			e.printStackTrace();
			Logger.log("Fail to send the ServerHello message!");
		} catch (CertificateEncodingException e) {
			e.printStackTrace();
			Logger.log("Fail to read the certificate file!");
		} catch (CertificateException e) {
			e.printStackTrace();
			Logger.log("Fail to encode the certificate!");
		}
    }
    
    public void receiveForward (Socket socket) {
    	HandshakeMessage forwardMessage = new HandshakeMessage();
    	try {
			forwardMessage.recv(socket);
			if (forwardMessage.getParameter("MessageType").equals("Forward")) {
				targetHost = forwardMessage.getParameter("TargetHost");
				targetPort = Integer.parseInt(forwardMessage.getParameter("TargetPort"));
				Logger.log("Agree to do port forwarding.");
			} else {
				throw new Exception();
			}
		} catch (IOException e) {
			e.printStackTrace();
			Logger.log("Fail to receive the forward message!");
		} catch (Exception e) {
			e.printStackTrace();
			Logger.log("Fail to deal with forward message!");
		}
    }
    
    public void session (Socket socket) {
    	HandshakeMessage sessionMessage = new HandshakeMessage();
    	sessionMessage.putParameter("MessageType","Session");
    	PublicKey clientPublicKey = clientCertificate.getPublicKey();
    	try {
			SessionEncrypter sessionEncrypter = new SessionEncrypter(128);
			sessionKey = sessionEncrypter.getKeyBytes();
			sessionIV = sessionEncrypter.getIVBytes();
			byte[] sessionKeyEncrypted =  HandshakeCrypto.encrypt(sessionKey, clientPublicKey);
			byte[] sessionIVEncrypted = HandshakeCrypto.encrypt(sessionIV, clientPublicKey);
			sessionMessage.putParameter("MessageType", "Session");
			sessionMessage.putParameter("SessionKey", Base64.getEncoder().encodeToString(sessionKeyEncrypted));
			sessionMessage.putParameter("SessionIV", Base64.getEncoder().encodeToString(sessionIVEncrypted));
			sessionMessage.putParameter("SessionHost", sessionHost);
			sessionMessage.putParameter("SessionPort", Integer.toString(sessionPort));
			sessionMessage.send(socket);	
			Logger.log("Session message sent!");
		}  catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException
				| InvalidParameterSpecException e) {
			e.printStackTrace();
			Logger.log("Fail to create session encrypter!");
		}   catch (IllegalBlockSizeException | BadPaddingException e) {
			e.printStackTrace();
			Logger.log("Fail to encrypt session key!");
		}   catch (IOException e) {
			e.printStackTrace();
			Logger.log("Fail to send the session message!");
		}
    }
}
