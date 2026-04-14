package emvcardsimulator;

import static org.junit.jupiter.api.Assertions.assertEquals;

import com.licel.jcardsim.utils.AIDUtil;

import javacard.framework.AID;
import javacard.framework.ISO7816;

import javax.smartcardio.CardException;
import javax.smartcardio.ResponseAPDU;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Tag;

import emvcardsimulator.ppse.ProximityPaymentSystemEnvironmentContainer;

/**
 * Contactless Mastercard Kernel 2 integration test.
 *
 * Installs PPSE + contactless payment applet into jcardsim,
 * personalizes with Mastercard data, then calls the Rust
 * terminal via JNI to run the full contactless kernel flow.
 */
@Tag("simulator")
public class ContactlessSimulatorTest {
    private static native void sendApduResponse(byte[] responseApdu);

    private static native void entryPointContactless(ContactlessSimulatorTest callback);

    // 2PAY.SYS.DDF01
    private static final byte[] PPSE_AID = new byte[] {
        (byte) 0x32, (byte) 0x50, (byte) 0x41, (byte) 0x59, (byte) 0x2E,
        (byte) 0x53, (byte) 0x59, (byte) 0x53, (byte) 0x2E,
        (byte) 0x44, (byte) 0x44, (byte) 0x46, (byte) 0x30, (byte) 0x31
    };

    // Default contactless AID: A0000009511010
    private static final byte[] MC_AID = new byte[] {
        (byte) 0xA0, (byte) 0x00, (byte) 0x00, (byte) 0x09,
        (byte) 0x51, (byte) 0x10, (byte) 0x10
    };

    @BeforeAll
    public static void setup() throws CardException {
        System.out.println("[CL-TEST] Loading native library...");
        System.loadLibrary("simulator");
        System.out.println("[CL-TEST] Native library loaded OK");

        SmartCard.setLogging(true);
        SmartCard.connect();
        System.out.println("[CL-TEST] SmartCard connected");

        // Install PPSE applet
        SmartCard.install(PPSE_AID, ProximityPaymentSystemEnvironmentContainer.class);
        System.out.println("[CL-TEST] PPSE installed");
        // Install contactless payment applet with default AID
        SmartCard.install(MC_AID, PaymentApplicationContainer.class);
        System.out.println("[CL-TEST] Payment app installed");
    }

    @AfterAll
    public static void disconnect() throws CardException {
        SmartCard.disconnect();
        SmartCard.setLogging(true);
    }

    @Test
    public void contactlessKernel2EndToEndTest() {
        ContactlessSimulatorTest.entryPointContactless(new ContactlessSimulatorTest());
    }

    /**
     * Proxy APDU request from Rust terminal to jcardsim.
     */
    public void sendApduRequest(byte[] requestApdu) {
        try {
            ResponseAPDU response = SmartCard.transmitCommand(requestApdu);
            sendApduResponse(response.getBytes());
        } catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        }
    }
}
