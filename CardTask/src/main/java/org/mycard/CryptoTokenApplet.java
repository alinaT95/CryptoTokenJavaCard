package org.mycard;

import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.Cipher;


public class CryptoTokenApplet extends Applet {

    public final static byte CRYPTOTOKEN_CARD_CLA = (byte) 0x80;

    /*
       Supported commands
    */
    public static final byte INS_WIPE_KEY = 0x10;
    public static final byte INS_VERIFY_PIN = 0x20;
    public static final byte INS_RSA_GEN_KEY_PAIR = 0x40;
    public static final byte INS_RSA_GET_PUB_KEY = 0x42;
    public static final byte INS_RSA_SIGN = 0x44;
    public static final byte INS_AES_GEN_KEY = 0x50;
    public static final byte INS_AES_UNWRAP_KEY = 0x52;
    public static final byte INS_AES_CALC_KCV = 0x54;
    public static final byte INS_AES_PROCESS = 0x56; // AES encryption/decryption

    private final static byte GET_PIN_TRIES_REMAINING = (byte) 0x59;

    /*
        Error codes
    */


    public final static short SW_WRAPPED_KEY_INVALID = 0x6984;
    public final static short SW_NO_ACTIVE_KEY = 0x6985;
    public final static short SW_PIN_IS_BLOCKED = 0x6983;
    public final static short SW_PIN_VERIFICATION_REQUIRED = 0x6982;
    public final static short SW_WRONG_PIN_SOME_TRIES_LEFT = (short) 0x63C0;


    /**
      Other constants
     */

    public static final byte PIN_TRY_LIMIT = 9;
    public static final byte PIN_SIZE = 8;
    public static final short RSA_KEY_SIZE_IN_BYTES = KeyBuilder.LENGTH_RSA_1024 / 8;

    public static final short SIGNATURE_SIZE = (short) 0x80;
    public static final short AES_KEY_SIZE_IN_BYTES = KeyBuilder.LENGTH_AES_128 / 8;

    public static final short BLOCK_SIZE = AES_KEY_SIZE_IN_BYTES;

    public static final short IV_SIZE = BLOCK_SIZE;

    public final static short KCV_LENGTH = 3;

    private final static short TMP_BUFFER_SIZE = (short) 512;


    private boolean keyPairPresent = false;

    private boolean aesKeyPresent = false;
    private boolean initializedAES = false;
    private boolean encryptionMode = true; // true = encryption, false = decryption
    private boolean kcvCalculated = false;

    OwnerPIN pin;

    private KeyPair rsaKeyPair;
    private RSAPublicKey publicKey;
    private Signature rsaSignature;
    private RandomData srng;
    private Cipher aesCipher;
    private AESKey key;

    private byte[] tmpBuffer;

    private byte[] keyData;

    private byte[] iv;

    private byte[] kcv;


    private CryptoTokenApplet(byte[] bArray, short bOffset, byte bLength) {
        byte maxPinTries = bArray[bOffset];
        if( (maxPinTries < 1) || (maxPinTries > PIN_TRY_LIMIT) ){
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
        byte pinLen = bArray[(short)(bOffset+1)];
        if( pinLen != PIN_SIZE ){
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        pin = new OwnerPIN(maxPinTries, pinLen);
        pin.update(bArray, (short)(bOffset+2), pinLen);
        rsaKeyPair = new KeyPair(KeyPair.ALG_RSA /*ALG_RSA_CRT*/, KeyBuilder.LENGTH_RSA_1024);
        rsaSignature = Signature.getInstance(Signature.ALG_RSA_SHA_256_PKCS1, false);
        srng = RandomData.getInstance(RandomData.ALG_PSEUDO_RANDOM);
        aesCipher = Cipher.getInstance(Cipher.ALG_AES_CBC_PKCS5, false);
        key = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
        iv = new byte[IV_SIZE];
        kcv = new byte[KCV_LENGTH];
        try {
            tmpBuffer = JCSystem.makeTransientByteArray(TMP_BUFFER_SIZE, JCSystem.CLEAR_ON_DESELECT);
            keyData = JCSystem.makeTransientByteArray(AES_KEY_SIZE_IN_BYTES, JCSystem.CLEAR_ON_DESELECT);
        } catch (SystemException e) {
            tmpBuffer = new byte[TMP_BUFFER_SIZE];
            keyData = new byte[AES_KEY_SIZE_IN_BYTES];
        }
        register();
    }

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        // create a Wallet applet instance
        byte aidLen = bArray[bOffset];
        bOffset += (short) (aidLen + 1);
        byte infoLen = bArray[bOffset];
        bOffset += (short) (infoLen + 1);
        byte dataLen = bArray[bOffset];
        bOffset += 1;

        new CryptoTokenApplet(bArray, bOffset, bLength);
    } // end of install method


    //@Override
    public void process(APDU apdu) {
        byte[] buffer = apdu.getBuffer();

        if (apdu.isISOInterindustryCLA()) {
            if (buffer[ISO7816.OFFSET_INS] == (byte) (0xA4)) {
                return;
            }
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }

        if (buffer[ISO7816.OFFSET_CLA] != CRYPTOTOKEN_CARD_CLA ) {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }

        switch (buffer[ISO7816.OFFSET_INS]) {
            case INS_AES_UNWRAP_KEY:
                this.aesUnwrapKey(apdu);
                return;
            case INS_AES_CALC_KCV:
                this.aesCalcKcv(apdu);
                return;
            case INS_AES_PROCESS:
                this.aesProcess(apdu);
                return;
            case INS_WIPE_KEY:
                this.wipeKey(apdu);
                return;
            case INS_AES_GEN_KEY:
                this.aesGenKey(apdu);
                return;
            case INS_VERIFY_PIN:
                this.verifyPIN(apdu);
                return;
            case GET_PIN_TRIES_REMAINING:
                getPinsRemaining(apdu);
                return;
            case INS_RSA_GEN_KEY_PAIR:
                this.rsaGenKeyPair(apdu);
                return;
            case INS_RSA_GET_PUB_KEY:
                this.rsaGetPubKey(apdu);
                return;
            case INS_RSA_SIGN:
                this.rsaSign(apdu);
                return;
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }

    } // end of process method

    private void verifyPIN(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        if (pin.getTriesRemaining() == 0) {
            ISOException.throwIt(SW_PIN_IS_BLOCKED);
        }
        byte byteRead = (byte) (apdu.setIncomingAndReceive());
        if ( (buffer[ISO7816.OFFSET_LC] != PIN_SIZE) || (byteRead != PIN_SIZE)) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        if (!pin.check(buffer, ISO7816.OFFSET_CDATA, PIN_SIZE)) {
            if (pin.getTriesRemaining() == 0) { //wipe key data
                keyPairPresent = false;
                rsaKeyPair.genKeyPair();
                aesKeyPresent = false;
                key.clearKey();
                kcvCalculated = false;
                Util.arrayFillNonAtomic(kcv, (short) 0x00, (short) kcv.length, (byte) 0x00);
            }
            ISOException.throwIt((short) (SW_WRONG_PIN_SOME_TRIES_LEFT | pin.getTriesRemaining()));
        }
    }

    //This function added only for external test convenience
    private void getPinsRemaining(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        if (pin.getTriesRemaining() == 0) {
            ISOException.throwIt(SW_PIN_IS_BLOCKED);
        }
        short le = apdu.setOutgoing();
        if (le != (byte) 1) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        apdu.setOutgoingLength((byte) 1);

        buffer[0] = (byte) pin.getTriesRemaining();
        apdu.sendBytes((short) 0, (short) 1);
    }


    private void wipeKey(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        if (pin.getTriesRemaining() == 0) {
            ISOException.throwIt(SW_PIN_IS_BLOCKED);
        }
        if (!pin.isValidated()) {
            ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
        }
        pin.reset();
        if(buffer[ISO7816.OFFSET_P1] < 1 || buffer[ISO7816.OFFSET_P1] > 3){
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
        //analyze P1
        if( ((buffer[ISO7816.OFFSET_P1] & (byte) 0x01) != 0) && keyPairPresent){
            keyPairPresent = false;
            rsaKeyPair.genKeyPair();
        }
        if( ((buffer[ISO7816.OFFSET_P1] & (byte) 0x02) != 0) && aesKeyPresent){
            aesKeyPresent = false;
            //Util.arrayFillNonAtomic(keyData, (short) 0x00, (short) keyData.length, (byte) 0x00);
            //key.setKey(keyData, (short) 0);
            key.clearKey();
            kcvCalculated = false;
            Util.arrayFillNonAtomic(kcv, (short) 0x00, (short) kcv.length, (byte) 0x00);
        }
    }

    private void aesGenKey(APDU apdu) {
        if (pin.getTriesRemaining() == 0) {
            ISOException.throwIt(SW_PIN_IS_BLOCKED);
        }
        if (!pin.isValidated()) {
            ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
        }
        pin.reset();
        srng.generateData(keyData, (short) 0, AES_KEY_SIZE_IN_BYTES);
        key.setKey(keyData, (short) 0);
        short le = apdu.setOutgoing();
        if (le != AES_KEY_SIZE_IN_BYTES) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        kcvCalculated = false;
        Util.arrayFillNonAtomic(kcv, (short) 0x00, (short) kcv.length, (byte) 0x00);
        aesKeyPresent = true;
        apdu.setOutgoingLength(AES_KEY_SIZE_IN_BYTES);
        apdu.sendBytesLong(keyData, (short) 0, AES_KEY_SIZE_IN_BYTES);
    }

    private void aesUnwrapKey(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        if (pin.getTriesRemaining() == 0) {
            ISOException.throwIt(SW_PIN_IS_BLOCKED);
        }
        if (!pin.isValidated()) {
            ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
        }
        pin.reset();

        short len = (short) (buffer[ISO7816.OFFSET_LC] & 0xFF);
        short byteRead = apdu.setIncomingAndReceive();
        if (len != 2 * AES_KEY_SIZE_IN_BYTES || len != byteRead)
            ISOException.throwIt(SW_WRAPPED_KEY_INVALID);

        aesCipher.init(key, Cipher.MODE_DECRYPT);
        short numOfEncryptedBytes = aesCipher.doFinal(buffer, ISO7816.OFFSET_CDATA, len, keyData, (short) 0);
        if (numOfEncryptedBytes != AES_KEY_SIZE_IN_BYTES)
            ISOException.throwIt(SW_WRAPPED_KEY_INVALID);
        key.setKey(keyData, (short) 0);
        aesKeyPresent = true;

        aesCipher.init(key, Cipher.MODE_ENCRYPT);
        Util.arrayFillNonAtomic(tmpBuffer, (short) 0, (short) tmpBuffer.length, (byte) 0);
        aesCipher.doFinal(tmpBuffer, (short) 0, BLOCK_SIZE, tmpBuffer, (short) (4 * BLOCK_SIZE));
        // Extract the first 3 bytes as KCV
        Util.arrayCopyNonAtomic(tmpBuffer, (short) (4 * BLOCK_SIZE), kcv, (short) 0, KCV_LENGTH);

        short le = apdu.setOutgoing();
        if (le != KCV_LENGTH) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        apdu.setOutgoingLength(KCV_LENGTH);
        kcvCalculated = true;
        apdu.sendBytesLong(kcv, (short) 0, KCV_LENGTH);
    }

    private void aesProcess(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        if (pin.getTriesRemaining() == 0) {
            ISOException.throwIt(SW_PIN_IS_BLOCKED);
        }
        if (!pin.isValidated()) {
            ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
        }
        pin.reset();
        if(!aesKeyPresent){
            ISOException.throwIt(SW_NO_ACTIVE_KEY);
        }
        switch (buffer[ISO7816.OFFSET_P1]) {
            case 0x01:
                this.aesInit(apdu);
                return;
            case 0x02:
                this.aesUpdate(apdu);
                return;
            case 0x03:
                this.aesFinalize(apdu);
                return;
            default:
                ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
    }

    private void aesInit(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        byte p2 = buffer[ISO7816.OFFSET_P2];
        boolean ivIncluded = ((p2 & (byte) 0x80) != 0);
        boolean encryption = ((p2 & (byte) 0x01) != 0);
        encryptionMode = encryption;
        initializedAES = true;
        short len = (short) (buffer[ISO7816.OFFSET_LC] &  (byte) 0xFF);
        short byteRead = apdu.setIncomingAndReceive();
        if ((ivIncluded && (len != IV_SIZE)) || len != byteRead)
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        if (ivIncluded) {
            Util.arrayCopyNonAtomic(buffer, ISO7816.OFFSET_CDATA, iv, (short) 0, IV_SIZE);
        } else {
            Util.arrayFillNonAtomic(iv, (short) 0, IV_SIZE, (byte) 0);
        }
        aesCipher.init(key, encryptionMode ? Cipher.MODE_ENCRYPT : Cipher.MODE_DECRYPT, iv, (short) 0, IV_SIZE);
    }

    private void aesCalcKcv(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        if (pin.getTriesRemaining() == 0) {
            ISOException.throwIt(SW_PIN_IS_BLOCKED);
        }
        if (!pin.isValidated()) {
            ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
        }
        pin.reset();
        if(!aesKeyPresent){
            ISOException.throwIt(SW_NO_ACTIVE_KEY);
        }
        if (!kcvCalculated) {
            // Initialize the cipher with the current key and all-zero IV
            aesCipher.init(key, Cipher.MODE_ENCRYPT);
            Util.arrayFillNonAtomic(tmpBuffer, (short) 0, (short) tmpBuffer.length, (byte) 0);
            aesCipher.doFinal(tmpBuffer, (short) 0, BLOCK_SIZE, tmpBuffer, (short) (4 * BLOCK_SIZE));
            // Extract the first 3 bytes as KCV
            Util.arrayCopyNonAtomic(tmpBuffer, (short) (4 * BLOCK_SIZE), kcv, (short) 0, KCV_LENGTH);

        }
        short le = apdu.setOutgoing();
        if (le != KCV_LENGTH) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        apdu.setOutgoingLength(KCV_LENGTH);
        kcvCalculated = true;
        apdu.sendBytesLong(kcv, (short) 0, KCV_LENGTH);
    }

    private void aesUpdate(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        if (!initializedAES) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        short len = (short) (buffer[ISO7816.OFFSET_LC] & 0xFF);
        short byteRead = apdu.setIncomingAndReceive();
        if (len == 0 || len != byteRead)
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        Util.arrayFillNonAtomic(tmpBuffer, (short) 0, (short) tmpBuffer.length, (byte) 0);
        short numOfProcessedBytes = aesCipher.update(buffer, ISO7816.OFFSET_CDATA, len, tmpBuffer, (short) 0);
        apdu.setOutgoing();
        apdu.setOutgoingLength(numOfProcessedBytes);
        apdu.sendBytesLong(tmpBuffer, (short) 0, numOfProcessedBytes);
    }

    private void aesFinalize(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        if (!initializedAES) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        short len = (short) (buffer[ISO7816.OFFSET_LC] & 0xFF);
        short byteRead = apdu.setIncomingAndReceive();
        if (len == 0 || len != byteRead)
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        apdu.setOutgoing();
        Util.arrayFillNonAtomic(tmpBuffer, (short) 0, (short) tmpBuffer.length, (byte) 0);
        short numOfProcessedBytes = aesCipher.doFinal(buffer, ISO7816.OFFSET_CDATA, len, tmpBuffer, (short) 0);
        initializedAES = false;
        apdu.setOutgoingLength(numOfProcessedBytes);
        apdu.sendBytesLong(tmpBuffer, (short) 0, numOfProcessedBytes);
    }

    private short ciphertextLen(short len) {
        return (short) (len + (BLOCK_SIZE - (len % BLOCK_SIZE)));
    }

    private void rsaGenKeyPair(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        if (pin.getTriesRemaining() == 0) {
            ISOException.throwIt(SW_PIN_IS_BLOCKED);
        }
        if (!pin.isValidated()) {
            ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
        }
        pin.reset();
        rsaKeyPair.genKeyPair();
        rsaSignature.init(rsaKeyPair.getPrivate(), Signature.MODE_SIGN);
        keyPairPresent = true;
        publicKey = (RSAPublicKey) rsaKeyPair.getPublic();
        // Prepare the response buffer
        short responseLength = serializeKey(buffer, (short) 0);
        // Send the response APDU
        apdu.setOutgoingAndSend((short) 0, responseLength);
    }

    private void rsaGetPubKey(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        if (pin.getTriesRemaining() == 0) {
            ISOException.throwIt(SW_PIN_IS_BLOCKED);
        }
        if (!pin.isValidated()){
            ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
        }
        pin.reset();
        if (!keyPairPresent) {
            ISOException.throwIt(SW_NO_ACTIVE_KEY);
        }
        publicKey = (RSAPublicKey) rsaKeyPair.getPublic();
        // Prepare the response buffer
        short responseLength = serializeKey(buffer, (short)0);
        // Send the response APDU
        apdu.setOutgoingAndSend((short) 0, responseLength);
    }

    private short serializeKey(byte[] buffer, short offset) {
        short expLen = publicKey.getExponent(buffer, (short) (offset + 2));
        Util.setShort(buffer, offset, expLen);
        short modLen = publicKey.getModulus(buffer, (short) (offset + 4 + expLen));
        Util.setShort(buffer, (short)(offset + 2 + expLen), modLen);
        return (short) (4 + expLen + modLen);
    }

    private void rsaSign(APDU apdu) {
        if (pin.getTriesRemaining() == 0) {
            ISOException.throwIt(SW_PIN_IS_BLOCKED);
        }
        if (!pin.isValidated()){
            ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
        }
        pin.reset();
        if (!keyPairPresent) {
            ISOException.throwIt(SW_NO_ACTIVE_KEY);
        }
        byte[] buffer = apdu.getBuffer();
        short len = (short) (buffer[ISO7816.OFFSET_LC] & 0xFF);
        short byteRead = apdu.setIncomingAndReceive();

        if (len == 0 || len != byteRead)
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);

        short le = apdu.setOutgoing();
        if (le != SIGNATURE_SIZE) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        rsaSignature.sign(buffer, ISO7816.OFFSET_CDATA, len, tmpBuffer, (short) 0);
        apdu.setOutgoingLength(SIGNATURE_SIZE);
        apdu.sendBytesLong(tmpBuffer, (short) 0, SIGNATURE_SIZE);
    }



}
