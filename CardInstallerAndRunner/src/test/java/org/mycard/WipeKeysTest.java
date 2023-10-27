package org.mycard;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.mycard.common.ByteArrayHelper;
import org.mycard.smartcard.pcscWrapper.CAPDU;
import org.mycard.smartcard.pcscWrapper.RAPDU;

import javax.smartcardio.CardException;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.RSAPublicKeySpec;

import static org.mycard.CardData.*;
import static org.mycard.HostAPI.testCard;

/**
 * Unit test for simple App.
 */
public class WipeKeysTest
        extends TestCase
{
    /**
     * Create the test case
     *
     * @param testName name of the test case
     */
    public WipeKeysTest(String testName )
    {
        super( testName );
    }

    /**
     * @return the suite of tests being tested
     */
    public static Test suite()
    {
        return new TestSuite( WipeKeysTest.class );
    }

    public void testWipePinFail() throws Exception
    {
        testCard(() -> {
            try {
                HostAPI.getCardReaderWrapper().getReader().selectAID(INSTANCE_AID);
                HostAPI.getCardReaderWrapper().getReader().sendAPDU(
                        new CAPDU(CRYPTOTOKEN_CARD_CLA, INS_WIPE_KEY, 0x00, 0x00));
            }
            catch (CardException e) {
                assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_PIN_VERIFICATION_REQUIRED)));
            }
        });
    }

    public void testWipeP1ValInvalid() throws Exception
    {
        testCard(() -> {
            HostAPI.getCardReaderWrapper().getReader().selectAID(INSTANCE_AID);
            byte[] wrongP1Vals = new byte[]{0x00, 0x04, 0x05};
            for(int i = 0; i < wrongP1Vals.length; i++){
                try {
                    RAPDU response = HostAPI.getCardReaderWrapper().getReader().sendAPDU(
                            new CAPDU(CRYPTOTOKEN_CARD_CLA, INS_VERIFY_PIN, 0x00, 0x00, PIN));
                    String sw = ByteArrayHelper.hex(response.getSW());
                    assertEquals("9000", sw);

                    HostAPI.getCardReaderWrapper().getReader().sendAPDU(
                            new CAPDU(CRYPTOTOKEN_CARD_CLA, INS_WIPE_KEY, wrongP1Vals[i] , 0x00));
                }
                catch (CardException e) {
                    assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_INCORRECT_P1P2)));
                }
            }
        });
    }

    public void testWipeRsaKey() throws Exception
    {
        testCard(() -> {
            HostAPI.getCardReaderWrapper().getReader().selectAID(INSTANCE_AID);

            RAPDU response = HostAPI.getCardReaderWrapper().getReader().sendAPDU(
                    new CAPDU(CRYPTOTOKEN_CARD_CLA, INS_VERIFY_PIN, 0x00, 0x00, PIN));
            String sw = ByteArrayHelper.hex(response.getSW());
            assertEquals("9000", sw);


            response = HostAPI.getCardReaderWrapper().getReader().sendAPDU(
                    new CAPDU(CRYPTOTOKEN_CARD_CLA, INS_RSA_GEN_KEY_PAIR, 0x00, 0x00, 0x00));

            sw = ByteArrayHelper.hex(response.getSW());
            assertEquals("9000", sw);
            assertTrue(response.getData().length > 3);

            response = HostAPI.getCardReaderWrapper().getReader().sendAPDU(
                    new CAPDU(CRYPTOTOKEN_CARD_CLA, INS_VERIFY_PIN, 0x00, 0x00, PIN));
            sw = ByteArrayHelper.hex(response.getSW());
            assertEquals("9000", sw);

            response = HostAPI.getCardReaderWrapper().getReader().sendAPDU(
                    new CAPDU(CRYPTOTOKEN_CARD_CLA, INS_RSA_GET_PUB_KEY, 0x00, 0x00, 0x00));
            assertEquals("9000", sw);
            assertTrue(response.getData().length > 3);

            response = HostAPI.getCardReaderWrapper().getReader().sendAPDU(
                    new CAPDU(CRYPTOTOKEN_CARD_CLA, INS_VERIFY_PIN, 0x00, 0x00, PIN));
            sw = ByteArrayHelper.hex(response.getSW());
            assertEquals("9000", sw);

            byte P1ToWipeRSAOnly = 0x01;
            response = HostAPI.getCardReaderWrapper().getReader().sendAPDU(
                    new CAPDU(CRYPTOTOKEN_CARD_CLA, INS_WIPE_KEY, P1ToWipeRSAOnly , 0x00));

            sw = ByteArrayHelper.hex(response.getSW());
            assertEquals("9000", sw);

            response = HostAPI.getCardReaderWrapper().getReader().sendAPDU(
                    new CAPDU(CRYPTOTOKEN_CARD_CLA, INS_VERIFY_PIN, 0x00, 0x00, PIN));
            sw = ByteArrayHelper.hex(response.getSW());
            assertEquals("9000", sw);

            try {
                HostAPI.getCardReaderWrapper().getReader().sendAPDU(
                        new CAPDU(CRYPTOTOKEN_CARD_CLA, INS_RSA_GET_PUB_KEY, 0x00, 0x00, 0x00));
                fail();
            }
            catch (CardException e) {
                assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_NO_ACTIVE_KEY)));
            }

            response = HostAPI.getCardReaderWrapper().getReader().sendAPDU(
                    new CAPDU(CRYPTOTOKEN_CARD_CLA, INS_VERIFY_PIN, 0x00, 0x00, PIN));
            sw = ByteArrayHelper.hex(response.getSW());
            assertEquals("9000", sw);

            try {
                byte[] dataToSign = new byte[]{0x01, 0x02, 0x03, 0x04};
                HostAPI.getCardReaderWrapper().getReader().sendAPDU(
                        new CAPDU(CRYPTOTOKEN_CARD_CLA, INS_RSA_SIGN, (byte) 0x00, (byte) 0x00, dataToSign, (byte) SIGNATURE_SIZE));
                fail();
            }
            catch (CardException e) {
                assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_NO_ACTIVE_KEY)));
            }

        });
    }

    public void testWipeAesKey() throws Exception
    {
        testCard(() -> {
            HostAPI.getCardReaderWrapper().getReader().selectAID(INSTANCE_AID);

            RAPDU response = HostAPI.getCardReaderWrapper().getReader().sendAPDU(
                    new CAPDU(CRYPTOTOKEN_CARD_CLA, INS_VERIFY_PIN, 0x00, 0x00, PIN));
            String sw = ByteArrayHelper.hex(response.getSW());
            assertEquals("9000", sw);

            response = HostAPI.getCardReaderWrapper().getReader().sendAPDU(
                    new CAPDU(CRYPTOTOKEN_CARD_CLA, INS_AES_GEN_KEY, 0x00, 0x00, (byte) AES_KEY_SIZE));
            sw = ByteArrayHelper.hex(response.getSW());
            assertEquals("9000", sw);

            response = HostAPI.getCardReaderWrapper().getReader().sendAPDU(
                    new CAPDU(CRYPTOTOKEN_CARD_CLA, INS_VERIFY_PIN, 0x00, 0x00, PIN));
            sw = ByteArrayHelper.hex(response.getSW());
            assertEquals("9000", sw);

            response = HostAPI.getCardReaderWrapper().getReader().sendAPDU(
                    new CAPDU(CRYPTOTOKEN_CARD_CLA, INS_AES_CALC_KCV, 0x00, 0x00, KCV_SIZE));
            sw = ByteArrayHelper.hex(response.getSW());
            assertEquals("9000", sw);

            response = HostAPI.getCardReaderWrapper().getReader().sendAPDU(
                    new CAPDU(CRYPTOTOKEN_CARD_CLA, INS_VERIFY_PIN, 0x00, 0x00, PIN));
            sw = ByteArrayHelper.hex(response.getSW());
            assertEquals("9000", sw);

            byte p1Init = 0x01;
            byte p2EncWithoutIv = 0x01;
            response = HostAPI.getCardReaderWrapper().getReader().sendAPDU(
                    new CAPDU(CRYPTOTOKEN_CARD_CLA, INS_AES_PROCESS, p1Init, p2EncWithoutIv));
            sw = ByteArrayHelper.hex(response.getSW());
            assertEquals("9000", sw);


            response = HostAPI.getCardReaderWrapper().getReader().sendAPDU(
                    new CAPDU(CRYPTOTOKEN_CARD_CLA, INS_VERIFY_PIN, 0x00, 0x00, PIN));
            sw = ByteArrayHelper.hex(response.getSW());
            assertEquals("9000", sw);

            byte P1ToWipeAesOnly = 0x02;
            response = HostAPI.getCardReaderWrapper().getReader().sendAPDU(
                    new CAPDU(CRYPTOTOKEN_CARD_CLA, INS_WIPE_KEY, P1ToWipeAesOnly , 0x00));
            sw = ByteArrayHelper.hex(response.getSW());
            assertEquals("9000", sw);


            response = HostAPI.getCardReaderWrapper().getReader().sendAPDU(
                    new CAPDU(CRYPTOTOKEN_CARD_CLA, INS_VERIFY_PIN, 0x00, 0x00, PIN));
            sw = ByteArrayHelper.hex(response.getSW());
            assertEquals("9000", sw);

            try {
                HostAPI.getCardReaderWrapper().getReader().sendAPDU(
                        new CAPDU(CRYPTOTOKEN_CARD_CLA, INS_AES_CALC_KCV, 0x00, 0x00, KCV_SIZE));
                fail();
            }
            catch (CardException e) {
                assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_NO_ACTIVE_KEY)));
            }


            response = HostAPI.getCardReaderWrapper().getReader().sendAPDU(
                    new CAPDU(CRYPTOTOKEN_CARD_CLA, INS_VERIFY_PIN, 0x00, 0x00, PIN));
            sw = ByteArrayHelper.hex(response.getSW());
            assertEquals("9000", sw);

            try {
                HostAPI.getCardReaderWrapper().getReader().sendAPDU(
                        new CAPDU(CRYPTOTOKEN_CARD_CLA, INS_AES_PROCESS, p1Init, p2EncWithoutIv));
                fail();
            }
            catch (CardException e) {
                assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_NO_ACTIVE_KEY)));
            }

            response = HostAPI.getCardReaderWrapper().getReader().sendAPDU(
                    new CAPDU(CRYPTOTOKEN_CARD_CLA, INS_VERIFY_PIN, 0x00, 0x00, PIN));
            sw = ByteArrayHelper.hex(response.getSW());
            assertEquals("9000", sw);

            try {
                byte[] data = new byte[]{1,2,3,4, 1,2,3,4, 1,2,3,4, 1,2,3, 4};
                String plainDataInHex = ByteArrayHelper.hex(data);
                byte p1Fin = 0x03;
                int le = data.length + (16 - (data.length % 16));
                HostAPI.getCardReaderWrapper().getReader().sendAPDU(
                        new CAPDU(CRYPTOTOKEN_CARD_CLA, INS_AES_PROCESS, p1Fin , (byte) 0x00, data, (byte) le));
                fail();
            }
            catch (CardException e) {
                assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_NO_ACTIVE_KEY)));
            }

        });
    }



}