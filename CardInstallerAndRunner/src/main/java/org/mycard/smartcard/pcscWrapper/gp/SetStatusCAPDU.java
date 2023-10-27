package org.mycard.smartcard.pcscWrapper.gp;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.mycard.smartcard.pcscWrapper.CAPDU;


public class SetStatusCAPDU extends CAPDU {
    final private static Logger log = LoggerFactory.getLogger(SetStatusCAPDU.class);


    public SetStatusCAPDU(byte[] aid, byte status) throws Exception {
        super((byte)0x80, (byte)0xF0, (byte) 0x40, status, aid);
    }


    @Override
    public String getDescr() {
        return "Set status";
    }


}


