package org.mycard.smartcard.pcscWrapper.gp;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.mycard.smartcard.pcscWrapper.CAPDU;

public class ExternalAuthenticateCAPDU extends CAPDU {
    final private static Logger log = LoggerFactory.getLogger(ExternalAuthenticateCAPDU.class);


    // Security level
    public static enum P1 {
        CDECR_CMAC_RMAC(0x13),
        CMAC_RMAC(0x11),
        RMAC(0x10),
        CDECR_CMAC(0x3),
        CMAC(0x1),
        NO_SECURE(0x0)
        ;

        public byte value;

        P1(int value) {
            this.value = (byte) value;
        }
    }

    public ExternalAuthenticateCAPDU(byte[] hostCrypt, P1 p1/*, SecureChannel secureChannel*/) throws Exception {
        super(0x84, 0x82, p1.value, 0x00, hostCrypt);
    }




    @Override
    public String getDescr() {
        return "External authenticate";
    }


}


