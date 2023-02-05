import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.math.BigInteger;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Random;
import java.security.MessageDigest;

public class Client implements Runnable {

    private Socket client;
    private boolean done;
    BigInteger prime = new BigInteger("1090748135619415929450294929359784500348155124953172211774101106966150168922785639028532473848836817769712164169076432969224698752674677662739994265785437233596157045970922338040698100507861033047312331823982435279475700199860971612732540528796554502867919746776983759391475987142521315878719577519148811830879919426939958487087540965716419167467499326156226529675209172277001377591248147563782880558861083327174154014975134893125116015776318890295960698011614157721282527539468816519319333337503114777192360412281721018955834377615480468479252748867320362385355596601795122806756217713579819870634321561907813255153703950795271232652404894983869492174481652303803498881366210508647263668376514131031102336837488999775744046733651827239395353540348414872854639719294694323450186884189822544540647226987292160693184734654941906936646576130260972193280317171696418971553954161446191759093719524951116705577362073481319296041201283516154269044389257727700289684119460283480452306204130024913879981135908026983868205969318167819680850998649694416907952712904962404937775789698917207356355227455066183815847669135530549755439819480321732925869069136146085326382334628745456398071603058051634209386708703306545903199608523824513729625136659128221100967735450519952404248198262813831097374261650380017277916975324134846574681307337017380830353680623216336949471306191686438249305686413380231046096450953594089375540285037292470929395114028305547452584962074309438151825437902976012891749355198678420603722034900311364893046495761404333938686140037848030916292543273684533640032637639100774502371542479302473698388692892420946478947733800387782741417786484770190108867879778991633218628640533982619322466154883011452291890252336487236086654396093853898628805813177559162076363154436494477507871294119841637867701722166609831201845484078070518041336869808398454625586921201308185638888082699408686536045192649569198110353659943111802300636106509865023943661829436426563007917282050894429388841748885398290707743052973605359277515749619730823773215894755121761467887865327707115573804264519206349215850195195364813387526811742474131549802130246506341207020335797706780705406945275438806265978516209706795702579244075380490231741030862614968783306207869687868108423639971983209077624758080499988275591392787267627182442892809646874228263172435642368588260139161962836121481966092745325488641054238839295138992979335446110090325230955276870524611359124918392740353154294858383359");
    BigInteger base = new BigInteger("5");
    private final BigInteger priv_key = generate_private_key();
    private final BigInteger pub_key = generate_public_key();
    SecretKeySpec key;

    @Override
    public void run() {
        try {
            client = new Socket("127.0.0.1", 5555);
            out = new PrintWriter(client.getOutputStream(), true);
            in = new BufferedReader(new InputStreamReader(client.getInputStream()));
            InputHandler inHandler = new InputHandler();
            Thread t = new Thread(inHandler);
            t.start();

            try {
                t.join();
            } catch (InterruptedException e) {
                shutdown();
            }

        } catch (IOException e) {
            shutdown();
        }
    }
    private BigInteger generate_private_key() {
        Random random = new Random(System.currentTimeMillis());
        StringBuilder key = new StringBuilder();
        for (int i = 0; i < 540; i++) {
            key.append(Integer.toHexString(random.nextInt(255)));
        }
        return new BigInteger(String.valueOf(key), 16);
    }

    private BigInteger generate_public_key() {
        return base.modPow(priv_key, prime);
    }

    private void get_key(BigInteger remote_pub_key) {
        BigInteger shared_secret = remote_pub_key.modPow(priv_key, prime);
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] messageDigest = md.digest(shared_secret.toByteArray());
            key = new SecretKeySpec(messageDigest, "AES");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    private String encrypt(String text) {
        byte[] encrypted_bytes = new byte[0];
        try {
            Cipher cipher = Cipher.getInstance("AES");
            byte[] byteContent = new byte[text.length()];
            for (int i = 0; i < text.length(); i++) {
                byteContent[i] = (byte) text.charAt(i);
            }
            cipher.init(Cipher.ENCRYPT_MODE, key);
            encrypted_bytes = cipher.doFinal(byteContent);

        } catch (NoSuchPaddingException | NoSuchAlgorithmException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
        }
        return Arrays.toString(encrypted_bytes);
    }

    private String decrypt(String encrypted) {
        byte[] decrypted_bytes = new byte[0];
        try {
            String[] byteValues = encrypted.substring(1, encrypted.length() - 1).split(",");
            byte[] bytes = new byte[byteValues.length];
            for (int i = 0, len = bytes.length; i < len; i++) {
                bytes[i] = Byte.parseByte(byteValues[i].trim());
            }
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, key);
            decrypted_bytes = cipher.doFinal(bytes);
        } catch (NoSuchPaddingException | NoSuchAlgorithmException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
        }
        return new String(decrypted_bytes);
    }

    public void shutdown() {
        done = true;

        try {
            in.close();
            out.close();
            if (!client.isClosed()) {
                client.close();
            }
            System.exit(0);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    class InputHandler implements Runnable {
        private BufferedReader in;
        private PrintWriter out;
        @Override
        public void run() {
            try {
                perform_key_exchange();
                BufferedReader msgReader = new BufferedReader(new InputStreamReader(System.in));
                out = new PrintWriter(client.getOutputStream(), true);
                in = new BufferedReader(new InputStreamReader(client.getInputStream()));
                while (!done) {
                    System.out.print(">> ");
                    String message = msgReader.readLine();
                    out.println(encrypt(message));
                    String response = decrypt(in.readLine());
                    if (response.equals("DISCONNECT")) {
                        System.out.println(response);
                        shutdown();
                        continue;
                    }

                    if (response.startsWith("RESPONSE")) {
                        String line;
                        while ((line = decrypt(in.readLine())).startsWith("RESPONSE"))
                            System.out.println(line.substring("RESPONSE".length()));

                        continue;
                    }

                    if (response.startsWith("ERROR")) {
                        System.out.println(response.substring("ERROR".length()));
                        continue;
                    }

                }

            } catch(IOException e) {
                e.printStackTrace();
                shutdown();
            }
        }


        private void perform_key_exchange() {
            try {
                out.println(pub_key);
                String remote_pub_key = in.readLine();
                System.out.println(remote_pub_key);
                get_key(new BigInteger(remote_pub_key));
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    public static void main(String[] args) {
        Client client = new Client();
        client.run();
    }
}
