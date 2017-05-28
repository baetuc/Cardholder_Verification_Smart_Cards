package Terminal;

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.lang3.Validate;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import java.io.*;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Security;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.LinkedList;
import java.util.List;

public class Terminal {
    private static final String PUBLIC_KEY_FILENAME = "public.txt";
    private static final String OUTPUT_FILE = "D:\\An 3\\Sem II\\SCA\\Loyalty\\apdu_scripts\\cvm.scr";
    private static final String INPUT_FILE = "D:\\An 3\\Sem II\\SCA\\Loyalty\\apdu_scripts\\input.txt";
    private static final String DELIMITER = "#";
    private static final String GARBAGE_LINE = "echo \"################################################################################################\";";

    private short lowerLimit;
    private short upperLimit;

    private List<Short> CVRs = new LinkedList<>();

//    private short CVR_1 = (short) 0x1F06; //  for payments less than $10, NO CVM REQUIRED
//    private short CVR_2 = (short) 0x0108; // for payments between $10 and $50, then plaintext PIN verification is required
//    private short CVR_3 = (short) 0x0409; // for payments above $50, then enciphered PIN verification is required

    private RSAPublicKey publicKey;
    private Cipher cipher;

    public Terminal() throws IOException, GeneralSecurityException, InterruptedException {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        BufferedReader br = new BufferedReader(new FileReader(PUBLIC_KEY_FILENAME));
        String encodedPublicKey = br.readLine();
        publicKey = (RSAPublicKey) loadPublicKey(encodedPublicKey);

        cipher = Cipher.getInstance("RSA/None/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);

        initiateCVM();
    }

    public void start() {
        while (true) {
            try {
                BufferedReader br = new BufferedReader(new InputStreamReader(System.in));

                System.out.println("Insert PIN: ");
                String PIN = br.readLine();

                boolean valid = true;
                for (int i = 0; i < PIN.length(); ++i) {
                    if (PIN.charAt(i) < '0' || PIN.charAt(i) > '9') {
                        System.out.println("Invalid PIN: " + PIN);
                        valid = false;
                        break;
                    }
                }
                if (!valid) {
                    continue;
                }

                System.out.println("Insert method (balance/credit/debit): ");
                String method = br.readLine().toLowerCase();

                switch (method) {
                    case "balance":
                        getBalance(PIN);
                        break;

                    case "credit":
                        credit(PIN, br);
                        break;

                    case "debit":
                        debit(PIN, br);
                        break;

                    default:
                        System.out.println("Invalid command: " + method);
                        continue;
                }


            } catch (IOException | InterruptedException | IllegalBlockSizeException | BadPaddingException | IllegalArgumentException e) {
                System.out.println(e.getMessage());
            }

        }
    }

    private void getBalance(String PIN) throws IOException, InterruptedException {
        String outputCommand = "0x80 0x50 0x00 0x00 0x00 0x02";
        writeCommandToFile(outputCommand);
        List<String> responses = getResponse();

        Validate.isTrue(responses.size() == 1, "Balance response is invalid!");

        R_APDU response = new R_APDU(responses.get(0));

        if (response.isError()) {
            System.out.println(response.getErrorMessage());
        } else {
            Validate.isTrue(response.hasResponse(), "Balance method invalid!");

            System.out.println("Balance: " + response.getResponse());
        }
    }

    private void credit(String PIN, BufferedReader br) throws IOException, InterruptedException {
        System.out.println("Insert amount: ");
        short amount;
        try {
            amount = Short.parseShort(br.readLine());
        } catch (NumberFormatException e) {
            throw new IOException("Amount is invalid");
        }

        String firstByte = " 0x" + Integer.toHexString((amount >> 8) & 0xff);
        String secondByte = " 0x" + Integer.toHexString(amount & 0xff);

        String outputCommand = "0x80 0x51 0x00 0x00 0x02" + firstByte + secondByte + " 0xf7";
        writeCommandToFile(outputCommand);

        List<String> responses = getResponse();

        Validate.isTrue(responses.size() == 1, "Credit response is invalid!");
        R_APDU response = new R_APDU(responses.get(0));

        if (response.isError()) {
            System.out.println(response.getErrorMessage());
        } else {
            Validate.isTrue(!response.hasResponse(), "Credit method invalid!");
            System.out.println("Credit method succeded!");
        }
    }

    private void debit(String PIN, BufferedReader br) throws IOException, InterruptedException, BadPaddingException, IllegalBlockSizeException {
        System.out.println("Insert amount: ");
        short amount;
        try {
            amount = Short.parseShort(br.readLine());
        } catch (NumberFormatException e) {
            throw new IOException("Amount is invalid");
        }

        String firstByte = " 0x" + Integer.toHexString((amount >> 8) & 0xff);
        String secondByte = " 0x" + Integer.toHexString(amount & 0xff);

        String outputCommand = "0x80 0x52 0x00 0x00 0x02" + firstByte + secondByte + " 0xf7";

        byte currentCase;
        if (amount < lowerLimit) {
            currentCase = 0x06;
        } else if (amount < upperLimit) {
            currentCase = 0x08;
        } else {
            currentCase = 0x09;
        }

        byte CVMCode = 0x00;
        for (short CVR : CVRs) {
            if ((CVR & 0xFF) == currentCase) { // the current element in list
                CVMCode = (byte) (CVR >> 8);
            }
        }

        String PINCommand;
        switch (CVMCode) {
            case 0x1F: // no CVM required
                PINCommand = noPINNeeded();

            case 0x01:
                PINCommand = verifyPlaintextPIN(PIN);
                break;

            case 0x04:
                PINCommand = verifyEncryptedPIN(PIN);
                break;

            default:
                System.out.println("Unrecognized CVM code: " + CVMCode);
                return;
        }

        writeCommandToFile(PINCommand + outputCommand);

        List<String> responses = getResponse();

        Validate.isTrue(responses.size() == 2, "Debit response is invalid!");

        R_APDU PINresponse = new R_APDU(responses.get(0));

        if (PINresponse.isError()) {
            System.out.println(PINresponse.getErrorMessage());
            return;
        }

        R_APDU response = new R_APDU(responses.get(1));

        if (response.isError()) {
            System.out.println(response.getErrorMessage());
        } else {
            Validate.isTrue(!response.hasResponse(), "Debit method invalid!");
            System.out.println("Debit method succeded!");
        }
    }

    private void initiateCVM() throws IOException, InterruptedException {
        String outputCommand = "0x80 0x20 0x00 0x00 0x00 0x7F";
        writeCommandToFile(outputCommand);

        List<String> responses = getResponse();

        Validate.isTrue(responses.size() == 1, "CVM initialization is invalid!");

        R_APDU response = new R_APDU(responses.get(0));

        if (response.isError()) {
            System.out.println(response.getErrorMessage());
            throw new IllegalArgumentException(response.getErrorMessage());
        }

        String[] originalResponse = response.getOriginalResponse();
        Validate.isTrue(originalResponse.length >= 5, "CVM list size is invalid: ", originalResponse.length);
        Validate.isTrue(originalResponse.length % 2 == 1, "CVM list size is invalid: ", originalResponse.length);

        lowerLimit = (short) (((short) ((stringToShort(originalResponse[1])) << 8)) + stringToShort(originalResponse[2]));
        upperLimit = (short) (((short) ((stringToShort(originalResponse[3])) << 8)) + stringToShort(originalResponse[4]));

        for (int i = 5; i < originalResponse.length; i += 2) {
            Short newCVR = (short) (((short) ((stringToShort(originalResponse[i])) << 8)) + stringToShort(originalResponse[i + 1]));
            CVRs.add(newCVR);
        }
    }

    private String noPINNeeded() {
        return "0x80 0x30 0x00 0x00 0x00 0x7F;\n";
    }

    private String verifyPlaintextPIN(String PIN) throws IOException, InterruptedException {
        String outputCommand = "0x80 0x30 0x00 0x00 ";
        outputCommand += (String.valueOf(PIN.length()) + " ");

        for (int i = 0; i < PIN.length(); ++i) {
            outputCommand += ("0x0" + PIN.charAt(i) + " ");
        }

        outputCommand += "0x7F;\n";

        return outputCommand;
    }

    private String verifyEncryptedPIN(String PIN) throws BadPaddingException, IllegalBlockSizeException, IOException, InterruptedException {
        byte[] PINBytes = new byte[PIN.length()];
        for (int i = 0; i < PIN.length(); ++i) {
            PINBytes[i] = (byte) (PIN.charAt(i) - '0');
        }

        byte[] encrypted = cipher.doFinal(PINBytes);

        String outputCommand = "0x80 0x40 0x00 0x00 ";

        outputCommand += "0x" + Integer.toHexString(encrypted.length & 0xff) + " ";

        String encryptedPIN = Hex.encodeHexString(encrypted);
        for (int i = 0; i < encryptedPIN.length(); i += 2) {
            outputCommand += ("0x" + encryptedPIN.charAt(i) + encryptedPIN.charAt(i + 1) + " ");
        }

        outputCommand += "0x7F;\n";

        return outputCommand;
    }

    private List<String> getResponse() throws IOException, InterruptedException {
        boolean found = false;
        List<String> response = new LinkedList<>();

        while (!found) {
            try {
                Thread.sleep(1000);
            } catch (InterruptedException e) {
                System.out.println(e.getMessage());
            }

            List<String> lines = Files.readAllLines(Paths.get(INPUT_FILE), Charset.defaultCharset());
            for (String line : lines) {
                if (!line.contains(DELIMITER)) {
                    found = true;
                    response.add(line);
                }
            }
        }

        new PrintWriter(INPUT_FILE).close(); // to delete all its contents

        return response;
    }

    private void writeCommandToFile(String command) throws IOException {
        BufferedWriter bw = new BufferedWriter(new FileWriter(OUTPUT_FILE));
        bw.write(command + ";");
        bw.newLine();

        for (int i = 0; i < 1000; ++i) {
            bw.write(GARBAGE_LINE);
            bw.newLine();
        }
        bw.close();
    }

    private PublicKey loadPublicKey(String stored) throws GeneralSecurityException {
        byte[] data = Base64.getDecoder().decode(stored);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(data);
        KeyFactory fact = KeyFactory.getInstance("RSA");
        return fact.generatePublic(spec);
    }

    private short stringToShort(String byteString) {
        return (short) (Integer.parseInt(byteString, 16) & 0xff);
    }

    public static void main(String[] args) throws IOException, GeneralSecurityException, InterruptedException {
        Terminal terminal = new Terminal();
        terminal.start();
    }
}
