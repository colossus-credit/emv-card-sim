package emvcardsimulator.ppse;

import javacard.framework.APDU;
import javacard.framework.ISOException;

/**
 * Unit testing applet abstraction container to catch and print any possible exceptions.
 */
public class ProximityPaymentSystemEnvironmentContainer extends ProximityPaymentSystemEnvironment {
    public static void install(byte[] buffer, short offset, byte length) {
        (new ProximityPaymentSystemEnvironmentContainer()).register();
    }

    /**
     * Process applet and print stack traces if any.
     */
    @Override
    public void process(APDU apdu) {
        try {
            super.process(apdu);
        } catch (ISOException e) {
            throw e;
        } catch (Exception e) {
            e.printStackTrace();
            throw e;
        }
    }
}
