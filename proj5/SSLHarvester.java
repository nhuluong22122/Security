package proj5;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.security.cert.X509Certificate;
import java.io.*;
import java.nio.charset.StandardCharsets;

/**
 * Program to collect certificate information from website
 * @author nhuluong
 */
public class SSLHarvester {
    static String REQUEST_BUFFER = "GET /robots.txt HTTP/1.1\r\n" +
            "Host: %s\r\n" +
            "\r\n";

    public static void main(String[] args) throws IOException{
        for(int i = 0; i < args.length; i++) {
            System.out.println(args[i]); //name of website
            String host = args[i].split(":")[0];
            Integer port = Integer.parseInt(args[i].split(":")[1]);

            SSLSocketFactory sslsocketfactory = (SSLSocketFactory) SSLSocketFactory.getDefault();
            SSLSocket sslsocket = (SSLSocket) sslsocketfactory.createSocket(host, port);

            //Establish SSL Connection
            BufferedReader reader = new BufferedReader(new InputStreamReader(sslsocket.getInputStream()));
            DataOutputStream out = new DataOutputStream(sslsocket.getOutputStream());
            SSLSession session = sslsocket.getSession();

            //Print X509 info
            System.out.println("CipherSuite: " + session.getCipherSuite());
            X509Certificate[] x509 = session.getPeerCertificateChain();
            for (int j = 0; j < x509.length; j++) {
                System.out.println("Subject: " + x509[j].getSubjectDN());
                System.out.println("Issuer: " + x509[j].getIssuerDN());
            }
            //Send out the Request Buffer
            out.write(String.format(REQUEST_BUFFER, host).getBytes(StandardCharsets.UTF_8));
            out.flush();
            String in = reader.readLine();
            if(in != null) System.out.println(in);
        }
    }
}
