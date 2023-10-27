package org.mycard.smartcard.pcscWrapper.gp;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.mycard.smartcard.pcscWrapper.CAPDU;

import static org.mycard.common.ByteArrayHelper.bConcat;
import static org.mycard.common.ByteArrayHelper.bytes;


public class DeleteCAPDU extends CAPDU {
    final private static Logger log = LoggerFactory.getLogger(DeleteCAPDU.class);

    public static enum P2 {
        OBJECT(0x00),
        OBJECT_AND_RELATED(0x80);

        private final byte value;

        P2(int value) {
            this.value = (byte) value;
        }
    }


    public DeleteCAPDU(byte[] aid, P2 p2) throws Exception {
        super(0x80, 0xE4, 0x00, p2.value, bConcat(bytes("4F"), new byte[]{(byte) aid.length}, aid));
    }




    @Override
    public String getDescr() {
        return "Delete";
    }


}


