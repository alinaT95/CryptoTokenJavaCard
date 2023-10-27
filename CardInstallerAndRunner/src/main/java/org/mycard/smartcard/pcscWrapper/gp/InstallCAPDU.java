package org.mycard.smartcard.pcscWrapper.gp;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.mycard.smartcard.pcscWrapper.CAPDU;

public class InstallCAPDU extends CAPDU {
    final private static Logger log = LoggerFactory.getLogger(InstallCAPDU.class);

    public static enum P1 {
        PERS(0x20),
        EXTR(0x10),
        MAKE_SELECTABLE(0x08),
        MAKE_INSTALL(0x04),
        MAKE_INSTALL_AND_SELECTABLE(0x0C),
        MAKE_LOAD(0x02);

        private final byte value;

        P1(int value) {
            this.value = (byte) value;
        }
    }


    public InstallCAPDU(P1 p1, byte[] data) throws Exception {
        super((byte)0x80, (byte)0xE6, p1.value, (byte)0x00, data);
    }




    @Override
    public String getDescr() {
        return "Delete";
    }


}


