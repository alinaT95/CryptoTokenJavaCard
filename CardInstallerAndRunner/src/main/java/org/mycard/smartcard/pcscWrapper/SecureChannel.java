package org.mycard.smartcard.pcscWrapper;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.mycard.smartcard.pcscWrapper.helpers.CryptoHelper;
import org.mycard.smartcard.pcscWrapper.helpers.SessionKeys;

import java.security.GeneralSecurityException;

import static org.mycard.common.ByteArrayHelper.*;


public class SecureChannel {
    final private static Logger log = LoggerFactory.getLogger(SecureChannel.class);

    private final SessionKeys sessionKeys;
    private byte[] macIcv = new byte[]{0, 0, 0, 0, 0, 0, 0, 0};

    public SecureChannel(SessionKeys sessionKeys) {
        this.sessionKeys = sessionKeys;
    }

    public CAPDU addMac(CAPDU command) throws GeneralSecurityException {

        byte cla = (command.getCla() == (byte) 0x80) ? (byte) 0x84 : command.getCla();

        // Generate mac
        byte[] mac = makeMac(
                cla,
                command.getIns(),
                command.getP1(),
                command.getP2(),
                command.getData()
        );

        return command.copy(
                cla,
                command.getIns(),
                command.getP1(),
                command.getP2(),
                bConcat(command.getData(), mac)
        );
    }

    public CAPDU addEncMac(CAPDU command) throws GeneralSecurityException {

        byte cla = (command.getCla() == (byte)  0x80) ? (byte) 0x84 : command.getCla();

        // Encrypt data
        byte[] dataEnc = CryptoHelper.encryptDes3CbcNoPadd(sessionKeys.encKey, CryptoHelper.padding(command.getData()));

        // Generate mac
        byte[] mac = makeMac(
                cla,
                command.getIns(),
                command.getP1(),
                command.getP2(),
                command.getData()
        );

        return command.copy(
                cla,
                command.getIns(),
                command.getP1(),
                command.getP2(),
                bConcat(dataEnc, mac)
        );
    }


    private final static int MAC_BLOCK_SIZE = 8;

    /**
     *
     * MAC generation, from spec:
     *
     * "Single DES Plus Final Triple DES MAC
     * This is also known as the Retail MAC. It is as defined in [ISO 9797-1] as MAC Algorithm 1"
     *
     * @param cla
     * @param ins
     * @param p1
     * @param p2
     * @param dataField
     * @return
     * @throws GeneralSecurityException
     */
    public byte[] makeMac(byte cla, byte ins, byte p1, byte p2, byte[] dataField) throws GeneralSecurityException {

        byte[] sMacSessionKey = sessionKeys.macKey;

        if (sMacSessionKey.length == 16) {
            byte[] temp = (byte[]) sMacSessionKey.clone();
            sMacSessionKey = new byte[24];
            System.arraycopy(temp, 0, sMacSessionKey, 0, temp.length);
            System.arraycopy(temp, 0, sMacSessionKey, 16, MAC_BLOCK_SIZE);
        }
        byte[] padding = {(byte) 0x80, 0, 0, 0, 0, 0, 0, 0};
        int paddingRequired = MAC_BLOCK_SIZE - (5 + dataField.length) % MAC_BLOCK_SIZE;
        byte[] data = new byte[5 + dataField.length + paddingRequired];

        //Build APDU
        data[0] = cla;
        data[1] = ins;
        data[2] = p1;
        data[3] = p2;
        data[4] = (byte) ((byte) dataField.length + (byte) 0x08);
        System.arraycopy(dataField, 0, data, 5, dataField.length);
        System.arraycopy(padding, 0, data, 5 + dataField.length, paddingRequired);


        // Keys used for MAC calculation
        byte[] key = bLeft(sMacSessionKey, MAC_BLOCK_SIZE);
        byte[] finalKey = sMacSessionKey;

        byte[] icv = macIcv; // initial value for ICV - last makeMac

        //Make simple DES for all but last block, use last macICV as IV for start
        if(data.length / MAC_BLOCK_SIZE>1)
        {
            byte[] secretAllButOne = CryptoHelper.encryptDesCbcNoPadd(key,bLeft(data, data.length - MAC_BLOCK_SIZE),icv);
            icv = bRight(secretAllButOne, MAC_BLOCK_SIZE);
        }

        //Make triple DES for last block, use it as open MAP
        byte[] cMac = CryptoHelper.encryptDes3CbcNoPadd(finalKey, bRight(data, MAC_BLOCK_SIZE), icv);

        // Encrypt MAC with single DES key (GP 2.1.1 - E.3.4 ICV Encryption)
        this.macIcv = CryptoHelper.encryptDesCbcNoPadd(key, cMac);

        return cMac;
    }
}
