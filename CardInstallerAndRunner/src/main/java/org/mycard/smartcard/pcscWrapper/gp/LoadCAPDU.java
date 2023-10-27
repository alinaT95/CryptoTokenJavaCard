package org.mycard.smartcard.pcscWrapper.gp;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.mycard.smartcard.pcscWrapper.CAPDU;

import java.util.ArrayList;
import java.util.List;

import static org.mycard.common.ByteArrayHelper.*;

public class LoadCAPDU extends CAPDU {
    final private static Logger log = LoggerFactory.getLogger(LoadCAPDU.class);


    public LoadCAPDU(byte blockNumber, byte[] data, boolean last) {
        super(0x80, 0xE8, last ? 0x80 : 0x00, blockNumber, data); //todo: use appropriate TLV structure
    }

//    private final static int MAX_DATA_PER_COMMAND = 237; // 255 - header - C4 tag header - MAC, also padding overhead
    private final static int MAX_DATA_PER_COMMAND = 196; // 255 - header - C4 tag header - MAC, also padding overhead

    public static List<LoadCAPDU> prepareCommands(byte[] fileData)
    {
        List<LoadCAPDU> result = new ArrayList<>();

        byte[] tlv = bConcat(new byte[]{(byte) 0xC4}, toLengthOctets(fileData.length), fileData); //todo: use TLV

        int blockNumber = 0;
        while(tlv.length>MAX_DATA_PER_COMMAND)
        {
            byte[] perCommand = bLeft(tlv, MAX_DATA_PER_COMMAND);
            result.add(new LoadCAPDU((byte) blockNumber, perCommand, false));

            blockNumber++;
            tlv = bRight(tlv, tlv.length - MAX_DATA_PER_COMMAND);
            //todo: check max block amount
        }
        result.add(new LoadCAPDU((byte) blockNumber, tlv, true));
        return result;

    }



    @Override
    public String getDescr() {
        return "Load";
    }



    //todo: REMOVE THESE FUNCTION! NEED TO USE TLV STRUCTURE
    public static final byte[] toLengthOctets(int i)
    {
        byte abyte0[] = null;
        if(i < 128)
        {
            abyte0 = new byte[1];
            abyte0[0] = (byte)i;
        } else
        {
            byte abyte1[] = intToBytes(i);
            abyte0 = new byte[1 + abyte1.length];
            System.arraycopy(abyte1, 0, abyte0, 1, abyte1.length);
            abyte0[0] = (byte)(abyte1.length | 0x80);
        }
        return abyte0;
    }

    public static final byte[] intToBytes(int i)
    {
        int j = (Integer.toHexString(i).length() + 1) / 2;
        byte abyte0[] = new byte[j];
        for(int k = 0; k < j; k++)
            abyte0[k] = (byte)(i >>> 8 * (j - 1 - k) & 0xff);

        return abyte0;
    }

}


