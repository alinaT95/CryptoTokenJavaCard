package org.mycard.smartcard.pcscWrapper.helpers;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;

import static org.mycard.common.ByteArrayHelper.*;


public class CryptoHelper {

    /**
     * DES padding according to Global Platform 2.1.1 specification
     */
    public static byte[] padding(byte[] dataForPadding) {

        dataForPadding = bConcat(dataForPadding, bytes("80"));
        while (dataForPadding.length % 8 != 0) {
            dataForPadding = bConcat(dataForPadding, bytes("00"));
        }
        return dataForPadding;
    }

    /**
     * Calculate MAC using 3DES in CBC mode with empty ICV, and taking
     * last crypto-block as MAC (used for calculate cryptograms)
     */
    public static byte[] macCryptogram(byte[] data, byte[] key) throws Exception {

        IvParameterSpec params = new IvParameterSpec(new byte[]{0, 0, 0, 0, 0, 0, 0, 0});

        if (key.length == 16) {
            byte[] temp = key.clone();
            key = new byte[24];
            System.arraycopy(temp, 0, key, 0, temp.length);
            System.arraycopy(temp, 0, key, 16, 8);
        }


        byte[] temp = null;
        SecretKey secretKey = new SecretKeySpec(key, "DESede");
        try {
            Cipher cbcDES = Cipher.getInstance("DESede/CBC/NoPadding");
            cbcDES.init(Cipher.ENCRYPT_MODE, secretKey, params);

            temp = cbcDES.doFinal(data); //todo: make padding
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
        }

        byte[] signature = new byte[8];
        System.arraycopy(temp, temp.length - 8, signature, 0, signature.length);
        return signature;
    }

    public static byte[] encryptDes3CbcNoPadd(byte[] key, byte[] dataForEncrypt) throws GeneralSecurityException {
        return encryptDes3CbcNoPadd(key, dataForEncrypt, new byte[]{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00} );
    }

    public static byte[] encryptDes3CbcNoPadd(byte[] key, byte[] dataForEncrypt, byte[] icv) throws GeneralSecurityException {
        DESedeKeySpec ks = new DESedeKeySpec(bConcat(key, bLeft(key, 8)));
        SecretKeyFactory kf = SecretKeyFactory.getInstance("DESede");
        SecretKey sk = kf.generateSecret(ks);
        Cipher c = Cipher.getInstance("DESede/CBC/NoPadding");
        IvParameterSpec ivSpec = new IvParameterSpec(icv);
        c.init(Cipher.ENCRYPT_MODE, sk, ivSpec);
        byte[] encData = c.doFinal(dataForEncrypt);
        return encData;
    }

    public static byte[] encryptDesCbcNoPadd(byte[] key, byte[] dataForEncrypt) throws GeneralSecurityException {
        return encryptDesCbcNoPadd(key, dataForEncrypt, new byte[]{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00});
    }

    public static byte[] encryptDesCbcNoPadd(byte[] key, byte[] dataForEncrypt, byte[] icv) throws GeneralSecurityException {
        DESKeySpec ks = new DESKeySpec(bConcat(key, bLeft(key, 8)));
        SecretKeyFactory kf = SecretKeyFactory.getInstance("DES");
        SecretKey sk = kf.generateSecret(ks);
        Cipher c = Cipher.getInstance("DES/CBC/NoPadding");
        IvParameterSpec ivSpec = new IvParameterSpec(icv);
        c.init(Cipher.ENCRYPT_MODE, sk, ivSpec);
        byte[] encData = c.doFinal(dataForEncrypt);
        return encData;
    }

}
