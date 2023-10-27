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
import java.util.HashSet;
import java.util.Set;

import static org.mycard.CardData.*;
import static org.mycard.HostAPI.testCard;

/**
 * Unit test for simple App.
 */
public class AESTest
        extends TestCase
{
    /**
     * Create the test case
     *
     * @param testName name of the test case
     */
    public AESTest(String testName )
    {
        super( testName );
    }

    /**
     * @return the suite of tests being tested
     */
    public static Test suite()
    {
        return new TestSuite( AESTest.class );
    }

    public void testAESKeyGen() throws Exception
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
        });
    }

    public void testAESKeyGenPinNotVerified() throws Exception
    {
        testCard(() -> {
            try {
                HostAPI.getCardReaderWrapper().getReader().selectAID(INSTANCE_AID);
                HostAPI.getCardReaderWrapper().getReader().sendAPDU(
                        new CAPDU(CRYPTOTOKEN_CARD_CLA, INS_AES_GEN_KEY, 0x00, 0x00, (byte) AES_KEY_SIZE));
            }
            catch (CardException e) {
                assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_PIN_VERIFICATION_REQUIRED)));
            }
        });
    }

    public void testAESProcessPinNotVerified() throws Exception
    {
        testCard(() -> {
            try {
                HostAPI.getCardReaderWrapper().getReader().selectAID(INSTANCE_AID);
                byte p1Init = 0x01;
                byte p2EncWithoutIv = 0x01;
                HostAPI.getCardReaderWrapper().getReader().sendAPDU(
                        new CAPDU(CRYPTOTOKEN_CARD_CLA, INS_AES_PROCESS, p1Init, p2EncWithoutIv));
            }
            catch (CardException e) {
                assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_PIN_VERIFICATION_REQUIRED)));
            }
        });
    }
    public void testAESInitFailWrongIv() throws Exception
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

            //Encryption

            byte p1Init = 0x01;
            byte p2EncWithIv = (byte) 0x81;

            try {
                HostAPI.getCardReaderWrapper().getReader().sendAPDU(
                        new CAPDU(CRYPTOTOKEN_CARD_CLA, INS_AES_PROCESS, p1Init, p2EncWithIv));
            }
            catch (CardException e) {
                assertTrue(e.getMessage().contains(ByteArrayHelper.hex(0x6700)));
            }


        });
    }



    public void testAESEncDecViaFinalize() throws Exception
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

            //Encryption

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

            byte[] data = new byte[]{1,2,3,4, 1,2,3,4, 1,2,3,4, 1,2,3, 4};
            String plainDataInHex = ByteArrayHelper.hex(data);
            byte p1Fin = 0x03;
            int expectedLe = data.length + (16 - (data.length % 16));
            response = HostAPI.getCardReaderWrapper().getReader().sendAPDU(
                    new CAPDU(CRYPTOTOKEN_CARD_CLA, INS_AES_PROCESS, p1Fin , (byte) 0x00, data, (byte) 0x00));
            sw = ByteArrayHelper.hex(response.getSW());
            assertEquals("9000", sw);

            byte[] ciphertext = response.getData();
            assertEquals(ciphertext.length, expectedLe);

            //Decryption

            response = HostAPI.getCardReaderWrapper().getReader().sendAPDU(
                    new CAPDU(CRYPTOTOKEN_CARD_CLA, INS_VERIFY_PIN, 0x00, 0x00, PIN));
            sw = ByteArrayHelper.hex(response.getSW());
            assertEquals("9000", sw);

            byte p2DecWithoutIv = 0x00;
            response = HostAPI.getCardReaderWrapper().getReader().sendAPDU(
                    new CAPDU(CRYPTOTOKEN_CARD_CLA, INS_AES_PROCESS, p1Init, p2DecWithoutIv));
            sw = ByteArrayHelper.hex(response.getSW());
            assertEquals("9000", sw);

            response = HostAPI.getCardReaderWrapper().getReader().sendAPDU(
                    new CAPDU(CRYPTOTOKEN_CARD_CLA, INS_VERIFY_PIN, 0x00, 0x00, PIN));
            sw = ByteArrayHelper.hex(response.getSW());
            assertEquals("9000", sw);

            response = HostAPI.getCardReaderWrapper().getReader().sendAPDU(
                    new CAPDU(CRYPTOTOKEN_CARD_CLA, INS_AES_PROCESS, p1Fin , (byte) 0x00, ciphertext, (byte) ciphertext.length));
            sw = ByteArrayHelper.hex(response.getSW());
            assertEquals("9000", sw);

            String decryptedDataInHex = ByteArrayHelper.hex(response.getData());
            System.out.println("Initial plaintext = \n" + plainDataInHex);
            System.out.println("Decrypted data (with extra zeros in the end after padding) = \n" + decryptedDataInHex);
            assertTrue(decryptedDataInHex.equals(plainDataInHex));


        });
    }

    public void testAESEncDecViaUpdatePlusFinalize() throws Exception
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

            //Encryption
            byte[] iv = new byte[]{1,2,3,4, 7,2,3,9, 1,2,9,4, 1,2,3, 6};
            byte[] data_block_1 = new byte[]{1,2,3,4, 1,2,3,4, 1,2,3,4, 1,2,3,9, 1,2,3,4, 1,2,3,4, 1,2,3,4, 1,2,3,9, 1,2,3,4, 1,2,3,4, 1,2,3,4, 1,2,3,9, 7, 8, 9, 6};
            byte[] data_block_2 = new byte[]{1,2,3,6, 1,2,3,6, 1,2,3,6, 1,2,7, 0, 3 ,4, 5, 6};
            String allDataInHex = ByteArrayHelper.hex(ByteArrayHelper.bConcat(data_block_1, data_block_2));

            byte[] ciphertext = new byte[]{};

            byte p1Init = 0x01;
            byte p2EncWithIv = (byte) 0x81;
            response = HostAPI.getCardReaderWrapper().getReader().sendAPDU(
                    new CAPDU(CRYPTOTOKEN_CARD_CLA, INS_AES_PROCESS, p1Init, p2EncWithIv, iv));
            sw = ByteArrayHelper.hex(response.getSW());
            assertEquals("9000", sw);

            response = HostAPI.getCardReaderWrapper().getReader().sendAPDU(
                    new CAPDU(CRYPTOTOKEN_CARD_CLA, INS_VERIFY_PIN, 0x00, 0x00, PIN));
            sw = ByteArrayHelper.hex(response.getSW());
            assertEquals("9000", sw);


            byte p1Update = 0x02;
            response = HostAPI.getCardReaderWrapper().getReader().sendAPDU(
                    new CAPDU(CRYPTOTOKEN_CARD_CLA, INS_AES_PROCESS, p1Update , (byte) 0x00, data_block_1, (byte) 0x00));
            sw = ByteArrayHelper.hex(response.getSW());
            assertEquals("9000", sw);

            ciphertext = ByteArrayHelper.bConcat(ciphertext, response.getData());


            response = HostAPI.getCardReaderWrapper().getReader().sendAPDU(
                    new CAPDU(CRYPTOTOKEN_CARD_CLA, INS_VERIFY_PIN, 0x00, 0x00, PIN));
            sw = ByteArrayHelper.hex(response.getSW());
            assertEquals("9000", sw);

            byte p1Fin = 0x03;
            response = HostAPI.getCardReaderWrapper().getReader().sendAPDU(
                    new CAPDU(CRYPTOTOKEN_CARD_CLA, INS_AES_PROCESS, p1Fin , (byte) 0x00, data_block_2, (byte) 0x00));
            sw = ByteArrayHelper.hex(response.getSW());
            assertEquals("9000", sw);

            ciphertext = ByteArrayHelper.bConcat(ciphertext, response.getData());


            //Decryption

            byte[] decryptedData = new byte[]{};
            byte ciphertextBytesPortionLen = 32;

            response = HostAPI.getCardReaderWrapper().getReader().sendAPDU(
                    new CAPDU(CRYPTOTOKEN_CARD_CLA, INS_VERIFY_PIN, 0x00, 0x00, PIN));
            sw = ByteArrayHelper.hex(response.getSW());
            assertEquals("9000", sw);

            byte p2DecWithIv = (byte)0x80;
            response = HostAPI.getCardReaderWrapper().getReader().sendAPDU(
                    new CAPDU(CRYPTOTOKEN_CARD_CLA, INS_AES_PROCESS, p1Init, p2DecWithIv, iv));
            sw = ByteArrayHelper.hex(response.getSW());
            assertEquals("9000", sw);

            response = HostAPI.getCardReaderWrapper().getReader().sendAPDU(
                    new CAPDU(CRYPTOTOKEN_CARD_CLA, INS_VERIFY_PIN, 0x00, 0x00, PIN));
            sw = ByteArrayHelper.hex(response.getSW());
            assertEquals("9000", sw);

            response = HostAPI.getCardReaderWrapper().getReader().sendAPDU(
                    new CAPDU(CRYPTOTOKEN_CARD_CLA, INS_AES_PROCESS, p1Update , (byte) 0x00, ByteArrayHelper.bSub(ciphertext, 0, ciphertextBytesPortionLen), (byte) 0x00));
            sw = ByteArrayHelper.hex(response.getSW());
            assertEquals("9000", sw);
            decryptedData = ByteArrayHelper.bConcat(decryptedData, response.getData());

            response = HostAPI.getCardReaderWrapper().getReader().sendAPDU(
                    new CAPDU(CRYPTOTOKEN_CARD_CLA, INS_VERIFY_PIN, 0x00, 0x00, PIN));
            sw = ByteArrayHelper.hex(response.getSW());
            assertEquals("9000", sw);

            response = HostAPI.getCardReaderWrapper().getReader().sendAPDU(
                    new CAPDU(CRYPTOTOKEN_CARD_CLA, INS_AES_PROCESS, p1Fin , (byte) 0x00, ByteArrayHelper.bSub(ciphertext, ciphertextBytesPortionLen), (byte) 0x00));
            sw = ByteArrayHelper.hex(response.getSW());
            assertEquals("9000", sw);
            decryptedData = ByteArrayHelper.bConcat(decryptedData, response.getData());

            String decryptedDataHex = ByteArrayHelper.hex(decryptedData);

            System.out.println(decryptedDataHex);
            System.out.println(allDataInHex);
            assertEquals(decryptedDataHex, allDataInHex);
            System.out.println(ByteArrayHelper.hex(ciphertext));

        });
    }

    public void testAESKcvPinFail() throws Exception
    {
        testCard(() -> {
            try {
                HostAPI.getCardReaderWrapper().getReader().selectAID(INSTANCE_AID);
                HostAPI.getCardReaderWrapper().getReader().sendAPDU(
                        new CAPDU(CRYPTOTOKEN_CARD_CLA, INS_AES_CALC_KCV, 0x00, 0x00, KCV_SIZE));
            }
            catch (CardException e) {
                assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_PIN_VERIFICATION_REQUIRED)));
            }
        });
    }

    public void testAESKcvSuccess() throws Exception
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
        });
    }

    public void testAESKcvChangeAfterKeyRegen() throws Exception {
        testCard(() -> {
            HostAPI.getCardReaderWrapper().getReader().selectAID(INSTANCE_AID);
            Set<String> kcv_set = new HashSet<>();
            for (int i = 0; i < 5; i++) {
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
                kcv_set.add(ByteArrayHelper.hex(response.getData()));
            }
            assertEquals(kcv_set.size(), 5);
        });
    }

    public void testAESKeyUnwrap() throws Exception
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
            String firstKcv = ByteArrayHelper.hex(response.getData());

            response = HostAPI.getCardReaderWrapper().getReader().sendAPDU(
                    new CAPDU(CRYPTOTOKEN_CARD_CLA, INS_VERIFY_PIN, 0x00, 0x00, PIN));
            sw = ByteArrayHelper.hex(response.getSW());
            assertEquals("9000", sw);

            byte[] newKeyData = new byte[]{0x09, 0x08, 0x06, 0x01, (byte) 0xC9, 0x18, (byte) 0xB6, 0x01, 0x09, 0x08, 0x06, 0x01, 0x09, 0x08, 0x06, 0x01};

            //Encryption

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

            byte p1Fin = 0x03;
            response = HostAPI.getCardReaderWrapper().getReader().sendAPDU(
                    new CAPDU(CRYPTOTOKEN_CARD_CLA, INS_AES_PROCESS, p1Fin , (byte) 0x00, newKeyData, (byte) 0x00));
            sw = ByteArrayHelper.hex(response.getSW());
            assertEquals("9000", sw);
            byte[] wrappedKey = response.getData();
            assertEquals(wrappedKey.length, 2 * AES_KEY_SIZE);


            //Wrapping

            response = HostAPI.getCardReaderWrapper().getReader().sendAPDU(
                    new CAPDU(CRYPTOTOKEN_CARD_CLA, INS_VERIFY_PIN, 0x00, 0x00, PIN));
            sw = ByteArrayHelper.hex(response.getSW());
            assertEquals("9000", sw);

            response = HostAPI.getCardReaderWrapper().getReader().sendAPDU(
                    new CAPDU(CRYPTOTOKEN_CARD_CLA, INS_AES_UNWRAP_KEY, (byte) 0x00, (byte) 0x00, wrappedKey, (byte) KCV_SIZE));
            sw = ByteArrayHelper.hex(response.getSW());
            assertEquals("9000", sw);
            String kcv = ByteArrayHelper.hex(response.getData());
            System.out.println(kcv);

            response = HostAPI.getCardReaderWrapper().getReader().sendAPDU(
                    new CAPDU(CRYPTOTOKEN_CARD_CLA, INS_VERIFY_PIN, 0x00, 0x00, PIN));
            sw = ByteArrayHelper.hex(response.getSW());
            assertEquals("9000", sw);


            response = HostAPI.getCardReaderWrapper().getReader().sendAPDU(
                    new CAPDU(CRYPTOTOKEN_CARD_CLA, INS_AES_CALC_KCV, 0x00, 0x00, KCV_SIZE));
            sw = ByteArrayHelper.hex(response.getSW());
            assertEquals("9000", sw);
            String secondKcv = ByteArrayHelper.hex(response.getData());
            System.out.println(secondKcv);
            assertTrue(kcv.equals(secondKcv));
            assertFalse(firstKcv.equals(secondKcv));

        });
    }

    public void testAESUnwrapPinFail() throws Exception
    {
        testCard(() -> {
            byte[] someKeyData = new byte[]{0x08, 0x06, 0x01, (byte) 0xC9, 0x18, (byte) 0xB6, 0x01, 0x09, 0x08, 0x06, 0x01, 0x09, 0x08, 0x06, 0x01};

            try {
                HostAPI.getCardReaderWrapper().getReader().selectAID(INSTANCE_AID);
                HostAPI.getCardReaderWrapper().getReader().sendAPDU(
                        new CAPDU(CRYPTOTOKEN_CARD_CLA, INS_AES_UNWRAP_KEY, (byte) 0x00, (byte) 0x00, someKeyData, (byte) KCV_SIZE));
            }
            catch (CardException e) {
                assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_PIN_VERIFICATION_REQUIRED)));
            }
        });
    }

    public void testAESUnwrapKeyFormatBad() throws Exception
    {
        testCard(() -> {
            byte[] someKeyData = new byte[]{0x08, 0x06, 0x01, (byte) 0xC9, 0x18, (byte) 0xB6, 0x01, 0x09, 0x08, 0x06, 0x01, 0x09, 0x08, 0x06, 0x01};
            RAPDU response = HostAPI.getCardReaderWrapper().getReader().sendAPDU(
                    new CAPDU(CRYPTOTOKEN_CARD_CLA, INS_VERIFY_PIN, 0x00, 0x00, PIN));
            String sw = ByteArrayHelper.hex(response.getSW());
            assertEquals("9000", sw);
            try {
                HostAPI.getCardReaderWrapper().getReader().selectAID(INSTANCE_AID);
                HostAPI.getCardReaderWrapper().getReader().sendAPDU(
                        new CAPDU(CRYPTOTOKEN_CARD_CLA, INS_AES_UNWRAP_KEY, (byte) 0x00, (byte) 0x00, someKeyData, (byte) KCV_SIZE));
            }
            catch (CardException e) {
                assertTrue(e.getMessage().contains(ByteArrayHelper.hex(SW_WRAPPED_KEY_INVALID)));
            }
        });
    }






}
