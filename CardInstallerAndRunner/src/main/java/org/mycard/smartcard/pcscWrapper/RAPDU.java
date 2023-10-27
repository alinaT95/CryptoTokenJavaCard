package org.mycard.smartcard.pcscWrapper;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.mycard.common.ByteArrayHelper.*;

public class RAPDU {
    final private static Logger log = LoggerFactory.getLogger(RAPDU.class);

    private final byte[] bytes;
    private final byte[] data; // TODO: redundant data, probably should be fixed
    private final byte[] sw;

    public RAPDU(byte[] bytes) {
        int len = bytes.length;
        this.bytes = bytes;
        this.data = new byte[len-2];
        System.arraycopy(bytes, 0, data, 0, len - 2);
        this.sw = new byte[]{bytes[len-2], bytes[len-1]};
    }

    public byte[] getData() {
        return data;
    }

    public byte[] getSW() {
        return sw;
    }

    public byte getSW1() {
        return sw[0];
    }

    public byte getSW2() {
        return sw[1];
    }

    public byte[] getBytes() {
        return bytes;
    }

    public static boolean isSuccess(RAPDU rapdu) {
        return rapdu.getSW1() == (byte)0x90 && rapdu.getSW2() == (byte)0x00;
    }


    @Override
    public String toString() {
        return "RAPDU "+ hex(getSW()) +
                (getData()!=null && getData().length>0
                ? " '"+ hex(getData())+"'"
                : "");
    }
}
