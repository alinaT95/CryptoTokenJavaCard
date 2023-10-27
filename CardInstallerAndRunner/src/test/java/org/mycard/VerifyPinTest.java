package org.mycard;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.mycard.common.ByteArrayHelper;
import org.mycard.smartcard.pcscWrapper.CAPDU;
import org.mycard.smartcard.pcscWrapper.RAPDU;

import javax.smartcardio.CardException;

import static org.mycard.CardData.*;
import static org.mycard.HostAPI.testCard;

/**
 * Unit test for simple App.
 */
public class VerifyPinTest
    extends TestCase
{
    /**
     * Create the test case
     *
     * @param testName name of the test case
     */
    public VerifyPinTest(String testName )
    {
        super( testName );
    }

    /**
     * @return the suite of tests being tested
     */
    public static Test suite()
    {
        return new TestSuite( VerifyPinTest.class );
    }


    public void testVerifyPinSuccess() throws Exception
    {
        testCard(() -> {
            HostAPI.getCardReaderWrapper().getReader().selectAID(INSTANCE_AID);
            RAPDU response = HostAPI.getCardReaderWrapper().getReader().sendAPDU(
                    new CAPDU(CRYPTOTOKEN_CARD_CLA, INS_VERIFY_PIN, 0x00, 0x00, PIN));
            String sw = ByteArrayHelper.hex(response.getSW());
            assertEquals("9000", sw);
        });
    }


    public void testVerifyPiFail() throws Exception
    {
        testCard(() -> {
            short expectedSW = 0;
            try {
                HostAPI.getCardReaderWrapper().getReader().selectAID(INSTANCE_AID);
                RAPDU response = HostAPI.getCardReaderWrapper().getReader().sendAPDU(
                        new CAPDU(CRYPTOTOKEN_CARD_CLA, INS_GET_PIN_TRIES_REMAINING, 0x00, 0x00, 0x01));
                byte pin_remaining_tries = response.getData()[0];
                System.out.println(pin_remaining_tries);
                byte[] BAD_PIN = new byte[]{0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x06};
                expectedSW =  pin_remaining_tries == 0 ? SW_PIN_IS_BLOCKED : (short) (SW_WRONG_PIN_SOME_TRIES_LEFT | (pin_remaining_tries - 1));
                HostAPI.getCardReaderWrapper().getReader().sendAPDU(
                        new CAPDU(CRYPTOTOKEN_CARD_CLA, INS_VERIFY_PIN, 0x00, 0x00, BAD_PIN));
                fail();
            }
            catch (CardException e) {
                assertTrue(e.getMessage().contains(ByteArrayHelper.hex(expectedSW)));
            }
        });

    }

    public void testPinBlocked() throws Exception
    {
        testCard(() -> {
            short expectedSW = 0;
            byte[] BAD_PIN = new byte[]{0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x06};
            HostAPI.getCardReaderWrapper().getReader().selectAID(INSTANCE_AID);


            while (true ) {
                RAPDU response = HostAPI.getCardReaderWrapper().getReader().sendAPDU(
                        new CAPDU(CRYPTOTOKEN_CARD_CLA, INS_GET_PIN_TRIES_REMAINING, 0x00, 0x00, 0x01));
                byte pin_remaining_tries = response.getData()[0];

                expectedSW =  (short) (SW_WRONG_PIN_SOME_TRIES_LEFT | (pin_remaining_tries - 1));
                try {
                    HostAPI.getCardReaderWrapper().getReader().sendAPDU(
                            new CAPDU(CRYPTOTOKEN_CARD_CLA, INS_VERIFY_PIN, 0x00, 0x00, BAD_PIN));
                    fail();
                }
                catch (Exception e) {
                    assertTrue(e.getMessage().contains(ByteArrayHelper.hex(expectedSW)));
                }

                if ( pin_remaining_tries == 1) {
                    break;
                }
            }

            try {
                HostAPI.getCardReaderWrapper().getReader().sendAPDU(
                        new CAPDU(CRYPTOTOKEN_CARD_CLA, INS_VERIFY_PIN, 0x00, 0x00, BAD_PIN));
                fail();
            }
            catch (Exception e) {
                assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_PIN_IS_BLOCKED)));
            }

            try {
                HostAPI.getCardReaderWrapper().getReader().sendAPDU(
                        new CAPDU(CRYPTOTOKEN_CARD_CLA, INS_RSA_GEN_KEY_PAIR, 0x00, 0x00, 0x00));
                fail();
            }
            catch (Exception e) {
                assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_PIN_IS_BLOCKED)));
            }

            try {
                HostAPI.getCardReaderWrapper().getReader().sendAPDU(
                        new CAPDU(CRYPTOTOKEN_CARD_CLA, INS_RSA_GET_PUB_KEY, 0x00, 0x00, 0x00));
                fail();
            }
            catch (Exception e) {
                assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_PIN_IS_BLOCKED)));
            }

            try {
                byte[] dataToSign = new byte[]{0x01, 0x02, 0x03, 0x04};

                HostAPI.getCardReaderWrapper().getReader().sendAPDU(
                        new CAPDU(CRYPTOTOKEN_CARD_CLA, INS_RSA_SIGN, (byte) 0x00, (byte) 0x00, dataToSign, (byte) SIGNATURE_SIZE));
                fail();
            }
            catch (Exception e) {
                assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_PIN_IS_BLOCKED)));
            }

            try {
                HostAPI.getCardReaderWrapper().getReader().sendAPDU(
                        new CAPDU(CRYPTOTOKEN_CARD_CLA, INS_AES_GEN_KEY, 0x00, 0x00, (byte) AES_KEY_SIZE));
                fail();
            }
            catch (Exception e) {
                assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_PIN_IS_BLOCKED)));
            }

            try {
                byte p1Init = 0x01;
                byte p2EncWithoutIv = 0x01;
                HostAPI.getCardReaderWrapper().getReader().sendAPDU(
                        new CAPDU(CRYPTOTOKEN_CARD_CLA, INS_AES_PROCESS, p1Init, p2EncWithoutIv));
                fail();
            }
            catch (Exception e) {
                assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_PIN_IS_BLOCKED)));
            }

            try {
                HostAPI.getCardReaderWrapper().getReader().sendAPDU(
                        new CAPDU(CRYPTOTOKEN_CARD_CLA, INS_WIPE_KEY, 0x00, 0x00));
                fail();
            }
            catch (Exception e) {
                assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_PIN_IS_BLOCKED)));
            }

            try {
                HostAPI.getCardReaderWrapper().getReader().sendAPDU(
                        new CAPDU(CRYPTOTOKEN_CARD_CLA, INS_AES_CALC_KCV, 0x00, 0x00, KCV_SIZE));
                fail();
            }
            catch (Exception e) {
                assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_PIN_IS_BLOCKED)));
            }

            byte[] someKeyData = new byte[]{0x08, 0x06, 0x01, (byte) 0xC9, 0x18, (byte) 0xB6, 0x01, 0x09, 0x08, 0x06, 0x01, 0x09, 0x08, 0x06, 0x01};

            try {
                HostAPI.getCardReaderWrapper().getReader().sendAPDU(
                        new CAPDU(CRYPTOTOKEN_CARD_CLA, INS_AES_UNWRAP_KEY, (byte) 0x00, (byte) 0x00, someKeyData, (byte) KCV_SIZE));
            }
            catch (CardException e) {
                assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_PIN_IS_BLOCKED)));
            }



        });

    }

}
