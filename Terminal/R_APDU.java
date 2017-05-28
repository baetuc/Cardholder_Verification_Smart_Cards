package Terminal;

public class R_APDU {
    // Response: CLA: 80, INS: 30, P1: 00, P2: 00, Lc: 05, 01, 02, 03, 04, 05, Le: 00, SW1: 90, SW2: 00
    // Response: CLA: 80, INS: 50, P1: 00, P2: 00, Lc: 00, Le: 02, 00, 1e, SW1: 90, SW2: 00
    private boolean isError;
    private boolean hasResponse;
    private short response;
    private String[] originalResponse;
    private String errorMessage;

    public R_APDU(String responseCode) {
        response = 0;
        isError = true;
        errorMessage = "";

        String trimmed = responseCode.substring(10); // delete "Response: " part
        trimmed = trimmed.substring(trimmed.indexOf("Le: ") + 4);

        int indexSW1 = trimmed.indexOf(", SW1: ");
        String Le = trimmed.substring(0, indexSW1);
        String[] leParts = Le.split(", "); // first is the length, skip

        originalResponse = leParts;
        if (leParts.length > 1) {
            hasResponse = true;
        }

        for (int i = 1; i < leParts.length; ++i) {
            response = (short) (response << 8);
            response |= stringToShort(leParts[i]);
        }

        String finalCode = "";
        String code = trimmed.substring(indexSW1 + 7);
        finalCode += code.substring(0, 2);
        finalCode += code.substring(9);

        finalCode = finalCode.toLowerCase();


        switch (finalCode) {
            case "9000":
                isError = false;
                break;

            case "6300":
                errorMessage = "Error! PIN Incorrect";
                break;

            case "6301":
                errorMessage = "Error! PIN required!";
                break;

            case "6302":
                errorMessage = "Error! PIN length exceeded!";
                break;

            case "6a83":
                errorMessage = "Error! Invalid transaction amount!";
                break;

            case "6a85":
                errorMessage = "Error! Maximum balance exceeded!";
                break;

            case "6a86":
                errorMessage = "Error! Insufficient funds!";
                break;

            default:
                errorMessage = "Error! Code: 0x" + finalCode + ".";
                break;
        }

    }

    private short stringToShort(String byteString) {
        return (short) (Integer.parseInt(byteString, 16) & 0xff);
    }

    public boolean isError() {
        return isError;
    }

    public boolean hasResponse() {
        return hasResponse;
    }

    public short getResponse() {
        return response;
    }

    public String getErrorMessage() {
        return errorMessage;
    }

    public String[] getOriginalResponse() {
        return originalResponse;
    }

    public static void main(String[] args) {
        String testResponse = "Response: CLA: 80, INS: 52, P1: 00, P2: 00, Lc: 02, 00, 05, Le: 00, SW1: 63, SW2: 01";
//        String testResponse = "Response: CLA: 80, INS: 50, P1: 00, P2: 00, Lc: 00, Le: 02, 00, 1e, SW1: 90, SW2: 00";
//        String testResponse = "Response: CLA: 80, INS: 30, P1: 00, P2: 00, Lc: 05, 01, 02, 03, 04, 05, Le: 00, SW1: 90, SW2: 00";
        R_APDU apdu = new R_APDU(testResponse);
        System.out.println(apdu.isError);
        System.out.println(apdu.errorMessage);
        System.out.println(apdu.response);
        System.out.println(apdu.hasResponse);
    }
}
