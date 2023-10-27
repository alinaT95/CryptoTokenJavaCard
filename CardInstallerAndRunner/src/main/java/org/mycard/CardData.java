package org.mycard;

public class CardData {
    public static final String LOAD_FILE_AID = "A00000006203010C06";
    public static final String MODULE_AID = "A00000006203010C0601";
    public static final String INSTANCE_AID = "A00000006203010C0601";

    public static final String SD_AID = "A000000003000001"; //AID of Card Manager

    public static final String SD_ENC_KEY = "404142434445464748494A4B4C4D4E4F";
    public static final String SD_MAC_KEY = "404142434445464748494A4B4C4D4E4F";
    public static final String SD_DEC_KEY = "404142434445464748494A4B4C4D4E4F";

    public static final String CAP_PATH = "mycard.cap";

    public static final byte MAX_PIN_ATTEMPTS = 9;
    public static final byte PIN_LEN = 8;
    public  static final byte[] PIN = new byte[]{0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05};

    public final static byte CRYPTOTOKEN_CARD_CLA = (byte) 0x80;

    public static final short SIGNATURE_SIZE = (short) 0x80;

    public static final short AES_KEY_SIZE = (short) 16;

    public static final short KCV_SIZE = (short) 3;

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

    public final static byte INS_GET_PIN_TRIES_REMAINING = (byte) 0x59;


    /*
        Error codes
    */

    public final static short SW_PIN_VERIFICATION_REQUIRED = 0x6982;
    //public final static short SW_VERIFICATION_FAILED = 0x6343;

    public final static short SW_WRAPPED_KEY_INVALID = 0x6984;

    public final static short SW_INCORRECT_P1P2 = 0x6A86;

    public final static short SW_PIN_IS_BLOCKED = 0x6983;

    public final static short SW_NO_ACTIVE_KEY = 0x6985;

    public final static short SW_WRONG_PIN_SOME_TRIES_LEFT = (short) 0x63C0;
}