package emvcardsimulator;

import javax.smartcardio.*;
import java.util.*;

public class TestGenAcDirect {
    public static void main(String[] args) throws Exception {
        TerminalFactory factory = TerminalFactory.getDefault();
        CardTerminal terminal = factory.terminals().list().get(0);
        Card card = terminal.connect("*");
        CardChannel channel = card.getBasicChannel();

        // Select application
        byte[] selectCmd = hexToBytes("00A4040007A0000009510001");
        ResponseAPDU resp = channel.transmit(new CommandAPDU(selectCmd));
        System.out.println("SELECT SW: " + String.format("%04X", resp.getSW()));

        // Check ICC private key status (diagnostic command 80 04 00 07)
        byte[] diagCmd = hexToBytes("8004000700");
        resp = channel.transmit(new CommandAPDU(diagCmd));
        System.out.println("Key Diagnostic SW: " + String.format("%04X", resp.getSW()));
        if (resp.getSW() == 0x9000 && resp.getData().length >= 4) {
            byte[] data = resp.getData();
            System.out.println("  Key present: " + (data[0] == 0x01));
            int keySize = ((data[1] & 0xFF) << 8) | (data[2] & 0xFF);
            System.out.println("  Key size: " + keySize + " bytes (" + (keySize * 8) + " bits)");
            System.out.println("  Key initialized: " + (data[3] == 0x01));
        }

        // GPO (required before GENERATE AC)
        // PDOL data: 83 04 27000000 (tag 83 + TTQ)
        byte[] gpoData = hexToBytes("830427000000");
        byte[] gpoCmd = new byte[5 + gpoData.length];
        gpoCmd[0] = (byte) 0x80;
        gpoCmd[1] = (byte) 0xA8;
        gpoCmd[2] = 0x00;
        gpoCmd[3] = 0x00;
        gpoCmd[4] = (byte) gpoData.length;
        System.arraycopy(gpoData, 0, gpoCmd, 5, gpoData.length);
        resp = channel.transmit(new CommandAPDU(gpoCmd));
        System.out.println("GPO SW: " + String.format("%04X", resp.getSW()));
        System.out.println("GPO Response: " + bytesToHex(resp.getData()));

        // GENERATE AC - exact command from terminal trace
        // 80 AE 80 00 3A + 58 bytes CDOL1 data + Le
        byte[] cdol1Data = hexToBytes(
            "000000000100" +  // 9F02 Amount
            "000000000000" +  // 9F03 Amount Other
            "0840" +          // 9F1A Country
            "0410000000" +    // 95 TVR (from terminal trace)
            "0840" +          // 5F2A Currency
            "260123" +        // 9A Date
            "00" +            // 9C Type
            "B6B2D781" +      // 9F37 UN (from terminal trace)
            "3132333435363738" +  // 9F1C Terminal ID
            "202020202020202020202020202020" +  // 9F16 Merchant ID (15 bytes)
            "000000000000"    // 9F01 Acquirer ID
        );

        byte[] genAcCmd = new byte[5 + cdol1Data.length + 1]; // +1 for Le
        genAcCmd[0] = (byte) 0x80;
        genAcCmd[1] = (byte) 0xAE;
        genAcCmd[2] = (byte) 0x80; // P1 = ARQC
        genAcCmd[3] = 0x00;        // P2
        genAcCmd[4] = (byte) cdol1Data.length; // Lc
        System.arraycopy(cdol1Data, 0, genAcCmd, 5, cdol1Data.length);
        genAcCmd[genAcCmd.length - 1] = 0x00; // Le

        System.out.println("\nGENAC CMD: " + bytesToHex(genAcCmd));
        System.out.println("CDOL1 Data length: " + cdol1Data.length + " bytes");

        resp = channel.transmit(new CommandAPDU(genAcCmd));
        System.out.println("\nGENAC Initial SW: " + String.format("%04X", resp.getSW()));
        System.out.println("GENAC Initial Response (" + resp.getData().length + " bytes): " + bytesToHex(resp.getData()));

        // Collect full response
        java.io.ByteArrayOutputStream fullResp = new java.io.ByteArrayOutputStream();
        fullResp.write(resp.getData());

        // Try GET RESPONSE if needed
        while (resp.getSW1() == 0x61) {
            byte[] getResp = new byte[] { 0x00, (byte)0xC0, 0x00, 0x00, (byte)resp.getSW2() };
            resp = channel.transmit(new CommandAPDU(getResp));
            System.out.println("GET RESPONSE SW: " + String.format("%04X", resp.getSW()) + ", data: " + resp.getData().length);
            fullResp.write(resp.getData());
        }

        // Also try if we got 6D00 with data
        if (resp.getSW() == 0x6D00) {
            byte[] getResp = hexToBytes("00C0000000");
            ResponseAPDU resp2 = channel.transmit(new CommandAPDU(getResp));
            System.out.println("GET RESPONSE (after 6D00) SW: " + String.format("%04X", resp2.getSW()));
            if (resp2.getData().length > 0) {
                System.out.println("GET RESPONSE data (" + resp2.getData().length + " bytes): " + bytesToHex(resp2.getData()));
                fullResp.write(resp2.getData());
            }
        }

        byte[] response = fullResp.toByteArray();
        System.out.println("\n=== FULL RESPONSE ===");
        System.out.println("Total length: " + response.length + " bytes");
        System.out.println("Hex: " + bytesToHex(response));

        // Check for 9F4B
        String respHex = bytesToHex(response);
        if (respHex.contains("9F4B")) {
            System.out.println("\n9F4B (SDAD) IS PRESENT ✓");
        } else {
            System.out.println("\n9F4B (SDAD) NOT PRESENT ✗");
        }

        card.disconnect(false);
    }

    static byte[] hexToBytes(String hex) {
        hex = hex.replaceAll("\\s", "");
        byte[] bytes = new byte[hex.length() / 2];
        for (int i = 0; i < bytes.length; i++) {
            bytes[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
        }
        return bytes;
    }

    static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) sb.append(String.format("%02X", b));
        return sb.toString();
    }
}
