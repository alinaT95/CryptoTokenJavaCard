package org.mycard.smartcard.pcscWrapper.helpers;



import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;

import static org.mycard.common.ByteArrayHelper.bytes;


public class KeysHelper {

    public static Keys deriveMasterKeys(String masterKey, String kdd) throws Exception {
        masterKey = masterKey + masterKey.substring(0, 16);

        String kddForDec = kdd.substring(kdd.length() - 12) + "F003" + kdd.substring(kdd.length() - 12) + "0F03";
        String kddForMac = kdd.substring(kdd.length() - 12) + "F002" + kdd.substring(kdd.length() - 12) + "0F02";
        String kddForEnc = kdd.substring(kdd.length() - 12) + "F001" + kdd.substring(kdd.length() - 12) + "0F01";

        byte[] encKey = deriveKeyECB(masterKey, kddForEnc);
        byte[] macKey = deriveKeyECB(masterKey, kddForMac);
        byte[] decKey = deriveKeyECB(masterKey, kddForDec);


        return new Keys(encKey, macKey, decKey);
    }

    /**
     * Session keys derivation according to EMV CPS
     *
     *
     * @param masterKeys master keys
     * @param cardResponse response for Initialize Update
     *
     * @return session keys
     * @throws Exception
     */
    public static SessionKeys deriveSessionKeys(Keys masterKeys, String cardResponse) throws Exception {

        String seqCounter = cardResponse.substring(24, 28);

        String forSessionCMACkey = "0101" + seqCounter + "000000000000000000000000";
        String forSessionDEKkey = "0181" + seqCounter + "000000000000000000000000";
        String forSessionENCkey = "0182" + seqCounter + "000000000000000000000000";

        byte[] sencKey = deriveEncryptionCBC(masterKeys.encKey, bytes(forSessionENCkey));
        byte[] smacKey = deriveEncryptionCBC(masterKeys.macKey, bytes(forSessionCMACkey));
        byte[] sdekKey = deriveEncryptionCBC(masterKeys.decKey, bytes(forSessionDEKkey));

        return new SessionKeys(sencKey,smacKey,sdekKey);
    }



    // Derive key by using DES for derived data with masterKey as a DES secret key

    private static byte[] encryptDES3_ECB(String key, String hexData) throws Exception {
        DESedeKeySpec ks = new DESedeKeySpec(bytes(key));
        SecretKeyFactory kf = SecretKeyFactory.getInstance("DESede");
        SecretKey sk = kf.generateSecret(ks);
        Cipher c = Cipher.getInstance("DESede/ECB/NoPadding");
        c.init(Cipher.ENCRYPT_MODE, sk);
        byte[] keyBytes = c.doFinal(bytes(hexData));
        return keyBytes;
    }

    private static byte[] deriveKeyECB(String masterKey, String deriveData) throws Exception {
        return encryptDES3_ECB(masterKey, deriveData);
    }


    private static byte[] deriveEncryptionCBC(byte[] keyData, byte[] data) throws GeneralSecurityException {
        //Key key = getSecretKey(keyData);
        if (keyData.length == 16) {
            byte[] temp = (byte[]) keyData.clone();
            keyData = new byte[24];
            System.arraycopy(temp, 0, keyData, 0, temp.length);
            System.arraycopy(temp, 0, keyData, 16, 8);
        }
        SecretKey secretKey = new SecretKeySpec(keyData, "DESede");
        IvParameterSpec dps =
                new IvParameterSpec(new byte[]{0, 0, 0, 0, 0, 0, 0, 0});

        String algorithm = "DESede/CBC/NoPadding";
        Cipher desedeCBCCipher = Cipher.getInstance(algorithm);
        desedeCBCCipher.init(Cipher.ENCRYPT_MODE, secretKey, dps);

        byte[] result = desedeCBCCipher.doFinal(data);
        //adjustParity(result);

        return result;
    }

}