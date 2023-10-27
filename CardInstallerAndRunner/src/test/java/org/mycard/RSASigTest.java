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
public class RSASigTest
        extends TestCase
{
    /**
     * Create the test case
     *
     * @param testName name of the test case
     */
    public RSASigTest(String testName )
    {
        super( testName );
    }

    /**
     * @return the suite of tests being tested
     */
    public static Test suite()
    {
        return new TestSuite( RSASigTest.class );
    }


    public void testRSAGetPubKeyFailBecausePinNotVerified() throws Exception
    {
        testCard(() -> {
            try {
                HostAPI.getCardReaderWrapper().getReader().selectAID(INSTANCE_AID);
                HostAPI.getCardReaderWrapper().getReader().sendAPDU(
                        new CAPDU(CRYPTOTOKEN_CARD_CLA, INS_RSA_GET_PUB_KEY, 0x00, 0x00, 0x00));
                fail();
            }
            catch (CardException e) {
                assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_PIN_VERIFICATION_REQUIRED)));
            }
        });
    }

    public void testRSAGenKeyFailBecausePinNotVerified() throws Exception
    {
        testCard(() -> {
            try {
                HostAPI.getCardReaderWrapper().getReader().selectAID(INSTANCE_AID);
                HostAPI.getCardReaderWrapper().getReader().sendAPDU(
                        new CAPDU(CRYPTOTOKEN_CARD_CLA, INS_RSA_GEN_KEY_PAIR, 0x00, 0x00, 0x00));
                fail();
            }
            catch (CardException e) {
                assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_PIN_VERIFICATION_REQUIRED)));
            }
        });
    }

    public void testRSAGetPubKeyPinStory() throws Exception
    {
        testCard(() -> {
            try {
                HostAPI.getCardReaderWrapper().getReader().selectAID(INSTANCE_AID);

                RAPDU response = HostAPI.getCardReaderWrapper().getReader().sendAPDU(
                        new CAPDU(CRYPTOTOKEN_CARD_CLA, INS_VERIFY_PIN, 0x00, 0x00, PIN));
                String sw = ByteArrayHelper.hex(response.getSW());
                assertEquals("9000", sw);


                response = HostAPI.getCardReaderWrapper().getReader().sendAPDU(
                        new CAPDU(CRYPTOTOKEN_CARD_CLA, INS_RSA_GET_PUB_KEY, 0x00, 0x00, 0x00));

                sw = ByteArrayHelper.hex(response.getSW());
                assertEquals("9000", sw);
                assertTrue(response.getData().length > 3);

                HostAPI.getCardReaderWrapper().getReader().sendAPDU(
                        new CAPDU(CRYPTOTOKEN_CARD_CLA, INS_RSA_GET_PUB_KEY, 0x00, 0x00, 0x00));

                fail();
            }
            catch (CardException e) {
                assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_PIN_VERIFICATION_REQUIRED)));
            }
        });
    }


    public void testRSAGenKeyPinStory() throws Exception
    {
        testCard(() -> {
            try {
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

                HostAPI.getCardReaderWrapper().getReader().sendAPDU(
                        new CAPDU(CRYPTOTOKEN_CARD_CLA, INS_RSA_GEN_KEY_PAIR, 0x00, 0x00, 0x00));

                fail();
            }
            catch (CardException e) {
                assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_PIN_VERIFICATION_REQUIRED)));
            }
        });
    }

    public void testRSASignPinStory() throws Exception
    {
        testCard(() -> {
            try {
                HostAPI.getCardReaderWrapper().getReader().selectAID(INSTANCE_AID);

                RAPDU response = HostAPI.getCardReaderWrapper().getReader().sendAPDU(
                        new CAPDU(CRYPTOTOKEN_CARD_CLA, INS_VERIFY_PIN, 0x00, 0x00, PIN));
                String sw = ByteArrayHelper.hex(response.getSW());
                assertEquals("9000", sw);

                response = HostAPI.getCardReaderWrapper().getReader().sendAPDU(
                        new CAPDU(CRYPTOTOKEN_CARD_CLA, INS_RSA_GEN_KEY_PAIR, 0x00, 0x00, 0x00));
                sw = ByteArrayHelper.hex(response.getSW());
                assertEquals("9000", sw);

                response = HostAPI.getCardReaderWrapper().getReader().sendAPDU(
                        new CAPDU(CRYPTOTOKEN_CARD_CLA, INS_VERIFY_PIN, 0x00, 0x00, PIN));
                sw = ByteArrayHelper.hex(response.getSW());
                assertEquals("9000", sw);

                byte[] dataToSign = new byte[]{0x01, 0x02, 0x03, 0x04};
                response = HostAPI.getCardReaderWrapper().getReader().sendAPDU(
                        new CAPDU(CRYPTOTOKEN_CARD_CLA, INS_RSA_SIGN, (byte) 0x00, (byte) 0x00, dataToSign, (byte) SIGNATURE_SIZE));
                sw = ByteArrayHelper.hex(response.getSW());
                assertEquals("9000", sw);

                HostAPI.getCardReaderWrapper().getReader().sendAPDU(
                        new CAPDU(CRYPTOTOKEN_CARD_CLA, INS_RSA_SIGN, (byte) 0x00, (byte) 0x00, dataToSign, (byte) SIGNATURE_SIZE));

                fail();
            }
            catch (CardException e) {
                assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_PIN_VERIFICATION_REQUIRED)));
            }
        });
    }


    public void testRSAGenKeyAndGetRsaPubKeyAndSignPositive() throws Exception
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


            byte[] savedRSAPublicKeyDataBytes = response.getData();
            String savedRSAPublicKeyData = ByteArrayHelper.hex(response.getData());
            System.out.println("savedRSAPublicKeyData = " + savedRSAPublicKeyData);

            short expLen = (short) ((savedRSAPublicKeyDataBytes[0] << 8) | (savedRSAPublicKeyDataBytes[1] & 0xFF));
            System.out.println(expLen);
            BigInteger exponent = new BigInteger(ByteArrayHelper.bSub(savedRSAPublicKeyDataBytes, 2, expLen));
            System.out.println("exponent = " + exponent);
            short modLen = (short) ((savedRSAPublicKeyDataBytes[2 + expLen] << 8) | (savedRSAPublicKeyDataBytes[2 + expLen + 1] & 0xFF));
            System.out.println(modLen);
            System.out.println(ByteArrayHelper.hex(ByteArrayHelper.bSub(savedRSAPublicKeyDataBytes, 4 + expLen, modLen)));
            BigInteger modulus = new BigInteger(1, ByteArrayHelper.bSub(savedRSAPublicKeyDataBytes, 4 + expLen, modLen));
            System.out.println("modulus = " + modulus);

            System.out.println(ByteArrayHelper.hex(ByteArrayHelper.bSub(savedRSAPublicKeyDataBytes, 4 + expLen, modLen)));


            response = HostAPI.getCardReaderWrapper().getReader().sendAPDU(
                    new CAPDU(CRYPTOTOKEN_CARD_CLA, INS_VERIFY_PIN, 0x00, 0x00, PIN));
            sw = ByteArrayHelper.hex(response.getSW());
            assertEquals("9000", sw);

            response = HostAPI.getCardReaderWrapper().getReader().sendAPDU(
                    new CAPDU(CRYPTOTOKEN_CARD_CLA, INS_RSA_GET_PUB_KEY, 0x00, 0x00, 0x00));
            assertEquals("9000", sw);
            assertTrue(response.getData().length > 3);
            assertEquals(ByteArrayHelper.hex(response.getData()), savedRSAPublicKeyData);

            response = HostAPI.getCardReaderWrapper().getReader().sendAPDU(
                    new CAPDU(CRYPTOTOKEN_CARD_CLA, INS_VERIFY_PIN, 0x00, 0x00, PIN));
            sw = ByteArrayHelper.hex(response.getSW());
            assertEquals("9000", sw);

            byte[] dataToSign = new byte[]{0x01, 0x02, 0x03, 0x04};

            response = HostAPI.getCardReaderWrapper().getReader().sendAPDU(
                    new CAPDU(CRYPTOTOKEN_CARD_CLA, INS_RSA_SIGN, (byte) 0x00, (byte) 0x00, dataToSign, (byte) SIGNATURE_SIZE));

            try {
                Signature publicSignature = Signature.getInstance("SHA256withRSA");
                PublicKey publicKey = KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(modulus, exponent));
                publicSignature.initVerify(publicKey);
                publicSignature.update(dataToSign);
                boolean res = publicSignature.verify(response.getData());
                System.out.println(res);
                assertTrue(res);
            }
            catch (Exception e) {
                fail();
                e.printStackTrace();
            }

        });
    }

    public void testGetRsaPubKeyAndSignFailSinceKeyPairNotPresent() throws Exception
    {
        testCard(() -> {
            HostAPI.getCardReaderWrapper().getReader().selectAID(INSTANCE_AID);

            //call wipe

            RAPDU response = HostAPI.getCardReaderWrapper().getReader().sendAPDU(
                    new CAPDU(CRYPTOTOKEN_CARD_CLA, INS_VERIFY_PIN, 0x00, 0x00, PIN));
            String sw = ByteArrayHelper.hex(response.getSW());
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




}
